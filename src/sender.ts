import * as assert from 'assert'
import * as crypto from 'crypto'
import * as Debug from 'debug'
import BigNumber from 'bignumber.js'
import * as IlpPacket from 'ilp-packet'
import { default as convert, PluginV1, PluginV2 } from 'ilp-compat-plugin'
import * as constants from './constants'
import * as encoding from './encoding'
import { dataToFulfillment, fulfillmentToCondition } from './condition'
import { SocketInfo, SocketCtrlMessage } from './socket';

const DEFAULT_TRANSFER_TIMEOUT = 30000
const STARTING_TRANSFER_AMOUNT = 1000
const TRANSFER_INCREASE = 1.1
const TRANSFER_DECREASE = 0.5

/** Parameters for the [`sendRequest`]{@link sendRequest} method */
export interface SendRequestParams {
  /** Shared secret from the Receiver (generated with the [`generateAddressAndSecret`]{@link Receiver.generateAddressAndSecret} method). */
  sharedSecret: Buffer

  /** Destination account of the Receiver (generated with the [`generateAddressAndSecret`]{@link Receiver.generateAddressAndSecret} method). */
  destinationAccount: string
  
  /** Amount to send, denominated in the minimum units on the sender's ledger */
  sourceAmount: BigNumber | string | number
  
  /** Data to send to the receiver (will be encrypted and authenticated) */
  data?: Buffer
  
  /** Minimum destination amount the receiver should accept, denominated in the minimum units of the receiver's ledger */
  minDestinationAmount?: BigNumber | string | number,
  
  /** Optional ID for the request, which is used to correlate requests and responses. Defaults to a random UInt32 */
  requestId?: number
  
  /** Expiry time for the ILP Prepare packet, defaults to 30 seconds from when the request is created */
  expiresAt?: Date
  
  /**
   * Option to use an unfulfillable condition. For example, this may be used to send test payments for quotes.
   *
   * It is recommended to either generate this using crypto.randomBytes(32) or Buffer.alloc(32, 0).
   * 
   * @deprecated Use ['useUnfulfillableCondition']{@link useUnfulfillableCondition} instead.
   */
  unfulfillableCondition?: Buffer

  /**
   * Send the request with an unfufillable condition.
   * 
   * This is used to establish the rate along a route as the receiver will not fulfill the payment but will report the amount they received.
   */
  useUnfulfillableCondition?: boolean

  /**
   * Information about the local socket to send to the remote socket on a connection
   */
  socketInfo?: SocketInfo

  /**
   * A control message to send to the remote socket on a connection
   */
  socketCtrl?: SocketCtrlMessage
}

/** Successful response indicating the payment was sent */
export interface PskResponse {

  /** Always true for PskResponses */
  fulfilled: boolean,

  // TODO should there be a field like "fulfilled" for developers who are not using Typescript?

  /**
   * Amount that the receiver says they received. Note: you must trust the receiver not to lie about this.
   *
   * If the PSK packet the receiver sends back is tampered with or otherwise not understandable, this will be set to 0.
   */
  destinationAmount: BigNumber,

  /**
   * Authenticated response from the receiver.
   *
   * If the PSK packet the receiver sends back is tampered with or otherwise not understandable, this will be set to an empty buffer.
   */
  data: Buffer

  /**
   * Information from the remote socket about its current state
   */
  socketInfo?: SocketInfo

  /**
   * A control message from the remote socket
   */
  socketCtrl?: SocketCtrlMessage
}

/** Error response indicating the payment was rejected */
export interface PskError {
  
  /** Always false for PskErrors */
  fulfilled: boolean

  /** ILP Error Code (for example, `'F99'`) */
  code: string

  /** Error message. Note this is **not** authenticated and does not necessarily come from the receiver */
  message: string

  /** ILP Address of the party that rejected the packet */
  triggeredBy: string
  
  /**
   * Amount that the receiver says they received. Note: you must trust the receiver not to lie about this.
   *
   * If the PSK packet the receiver sends back is tampered with or otherwise not understandable, this will be set to 0.
   */
  destinationAmount: BigNumber

  /**
   * Authenticated response from the receiver.
   *
   * If the PSK packet the receiver sends back is tampered with or otherwise not understandable, this will be set to an empty buffer.
   */
  data: Buffer

  /**
   * Information from the remote socket about its current state
   */
  socketInfo?: SocketInfo

  /**
   * A control message from the remote socket
   */
  socketCtrl?: SocketCtrlMessage
}

export function isPskResponse (result: PskResponse | PskError): result is PskResponse {
  return result.fulfilled
}

export function isPskError (result: PskResponse | PskError): result is PskError {
  return !result.fulfilled
}

/**
 * Send a PSK2 request. This may be any of: a one-off payment, an unfulfillable packet for a quote, or one chunk of a streaming payment.
 *
 * @example <caption>One-off payment</caption>
 * ```typescript
 *   import { sendRequest } from 'ilp-protocol-psk2'
 *
 *   // These values must be communicated beforehand for the sender to send a payment
 *   const { destinationAccount, sharedSecret } = await getAddressAndSecretFromReceiver()
 *
 *   const { destinationAmount, data } = await sendRequest(myLedgerPlugin, {
 *     destinationAccount,
 *     sharedSecret,
 *     destinationAmount: '1000',
 *     data: Buffer.from('hello', 'utf8')
 *   })
 *
 *   console.log(`Sent payment of: 1000. Receiver got: ${result.destinationAmount}`)
 *   console.log(`Receiver responded: ${data.toString('utf8')}`)
 *   // Note the data encoding and content is up to the application
 * ```
 *
 * @example <caption>Quote (unfulfillable test payment)</caption>
 * ```typescript
 *   import { sendRequest } from 'ilp-protocol-psk2'
 *
 *   // These values must be communicated beforehand for the sender to send a payment
 *   const { destinationAccount, sharedSecret } = await getAddressAndSecretFromReceiver()
 *
 *   const { destinationAmount, data } = await sendRequest(myLedgerPlugin, {
 *     destinationAccount,
 *     sharedSecret,
 *     destinationAmount: '1000',
 *     unfulfillableCondition: 'random'
 *   })
 *   const rate = destinationAmount.dividedBy('1000')
 *
 *   console.log(`Path exchange rate is: ${rate}`)
 * ```
 */
export async function sendRequest (plugin: PluginV2, params: SendRequestParams): Promise<PskResponse | PskError> {
  const debug = Debug('ilp-protocol-psk3:sendRequest')

  const requestId = (typeof params.requestId === 'number' ? params.requestId : Math.floor(Math.random() * (constants.MAX_UINT32 + 1)))
  const sourceAmount = new BigNumber(params.sourceAmount)

  // If the minDestinationAmount is provided, use that
  // Otherwise, set it to 0 unless the unfulfillableCondition is set, in which case we set it to the maximum value
  // (This ensures that receivers will respond with the amount they received, as long as they check the amount before the condition)
  let minDestinationAmount: BigNumber
  if (params.minDestinationAmount !== undefined) {
    minDestinationAmount = new BigNumber(params.minDestinationAmount)
  } else if (params.unfulfillableCondition !== undefined) {
    minDestinationAmount = constants.MAX_UINT64
  } else {
    minDestinationAmount = new BigNumber(0)
  }
  assert(Number.isInteger(requestId) && requestId <= constants.MAX_UINT32, 'requestId must be a UInt32')
  assert(sourceAmount.isInteger() && sourceAmount.isLessThanOrEqualTo(constants.MAX_UINT64), 'sourceAmount must be a UInt64')
  assert(minDestinationAmount.isInteger() && minDestinationAmount.isLessThanOrEqualTo(constants.MAX_UINT64), 'minDestinationAmount must be a UInt64')

  // TODO enforce data limit

  //TODO Validate socket info and ctrl messages

  //Construct PSK Packet
  const pskPacket = encoding.serializePskPacket(
    params.sharedSecret, 
    {
      type: encoding.Type.Request,
      requestId,
      amount: new BigNumber(params.minDestinationAmount || 0),
      data: params.data || Buffer.alloc(0) 
    },
    params.socketCtrl, 
    params.socketInfo
  )

  let fulfillment
  let executionCondition
  if (params.unfulfillableCondition) {
    assert(params.unfulfillableCondition.length === 32, 'unfulfillableCondition must be 32 bytes')
    debug(`using user-specified unfulfillable condition for request: ${requestId}`)
    executionCondition = params.unfulfillableCondition
  } else if(params.unfulfillableCondition) {
    executionCondition = crypto.randomBytes(32)
  } else {
    fulfillment = dataToFulfillment(params.sharedSecret, pskPacket)
    executionCondition = fulfillmentToCondition(fulfillment)
  }

  //Construct ILP Prepare Packet
  const prepare = IlpPacket.serializeIlpPrepare({
    destination: params.destinationAccount,
    amount: new BigNumber(params.sourceAmount).toString(10),
    executionCondition,
    expiresAt: params.expiresAt || new Date(Date.now() + DEFAULT_TRANSFER_TIMEOUT),
    data: pskPacket
  })

  //Send ILP Prepare and get either ILP Fulfill or ILP Reject
  debug(`sending request ${requestId} for amount: ${params.sourceAmount}`)
  const response = await plugin.sendData(prepare)

  if (!Buffer.isBuffer(response) || response.length === 0) {
    throw new Error('Got empty response from plugin.sendData')
  }

  let packet: IlpPacket.IlpFulfill | IlpPacket.IlpRejection
  try {
    const parsed = IlpPacket.deserializeIlpPacket(response)
    if (parsed.type === IlpPacket.Type.TYPE_ILP_FULFILL || parsed.type === IlpPacket.Type.TYPE_ILP_REJECT) {
      packet = parsed.data as IlpPacket.IlpFulfill | IlpPacket.IlpRejection
    } else {
      throw new Error('Unexpected ILP packet type: ' + parsed.type)
    }
  } catch (err) {
    debug('error parsing prepare response:', err, response && response.toString('hex'))
    throw new Error('Unable to parse response from plugin.sendData')
  }

  let pskResponsePacket: encoding.PskPacket
  if (packet.data.length > 0) {
    try {
      pskResponsePacket = encoding.deserializePskPacket(params.sharedSecret, packet.data)
    } catch (err) {
      debug('error parsing PSK response packet:', packet.data.toString('hex'), err)
    }
  }
  /* tslint:disable-next-line:no-unnecessary-type-assertion */
  pskResponsePacket = pskResponsePacket!

  // Return the fields from the response packet only if the request ID and PSK packet type are what we expect
  let destinationAmount
  let data
  let socketInfo
  let socketCtrl
  const expectedType = (isFulfill(packet) ? encoding.Type.Response : encoding.Type.Error)
  if (!pskResponsePacket) {
    destinationAmount = new BigNumber(0)
    data = Buffer.alloc(0)
  } else if (pskResponsePacket.type !== expectedType) {
    console.warn(`Received PSK response packet whose type should be ${expectedType} but is ${pskResponsePacket.type}. Either the receiver is faulty or a connector is messing with us`)
    destinationAmount = new BigNumber(0)
    data = Buffer.alloc(0)
  } else if (pskResponsePacket.requestId !== requestId) {
    console.warn(`Received PSK response packet whose ID (${pskResponsePacket.requestId}) does not match our request (${requestId}). either the receiver is faulty or a connector is messing with us`)
    destinationAmount = new BigNumber(0)
    data = Buffer.alloc(0)
  } else {
    destinationAmount = pskResponsePacket.amount
    data = pskResponsePacket.data
    socketInfo = pskResponsePacket.socketInfo
    socketCtrl = pskResponsePacket.socketCtrl
  }

  if (isFulfill(packet)) {
    debug(`request ${requestId} was fulfilled`)
    return {
      fulfilled: true,
      destinationAmount,
      data,
      socketInfo,
      socketCtrl
    }
  } else {
    debug(`request ${requestId} was rejected with code: ${packet.code}`)
    return {
      fulfilled: false,
      code: packet.code,
      message: packet.message,
      triggeredBy: packet.triggeredBy,
      destinationAmount,
      data,
      socketInfo,
      socketCtrl
    }
  }
}

function isFulfill (packet: IlpPacket.IlpFulfill | IlpPacket.IlpRejection): packet is IlpPacket.IlpFulfill {
  return packet.hasOwnProperty('fulfillment')
}