'use strict'

import * as assert from 'assert'
import * as crypto from 'crypto'
import * as Debug from 'debug'
const debug = Debug('ilp-protocol-psk2:receiver')
import BigNumber from 'bignumber.js'
import { PluginV2 } from 'ilp-compat-plugin'
import IlpPacket = require('ilp-packet')
import * as constants from './constants'
import * as encoding from './encoding'
import { dataToFulfillment, fulfillmentToCondition } from './condition'
import * as ILDCP from 'ilp-protocol-ildcp'
import { SocketInfo, SocketCtrlMessage } from './socket';

const PSK_GENERATION_STRING = 'ilp_psk2_generation'
const PSK_ADDRESS_FROM_SECRET_STRING = 'ilp_psk2_address_from_secret'
const TOKEN_LENGTH = 18
const SHARED_SECRET_LENGTH = 32

/**
 * Review callback that will be called every time the Receiver receives an incoming packet.
 *
 * The RequestHandler can call [`accept`]{@link RequestHandlerParams.accept} to fulfill the packet or [`reject`]{@link RequestHandlerParams.reject} to reject it.
 */
export interface RequestHandler {
  (params: RequestHandlerParams): Promise<void>
}

export interface RequestHandlerParams {

  /** If a keyId was passed into [`createAddressAndSecret`]{@link Receiver.createAddressAndSecret}, it will be present here when a packet is sent to that `destinationAccount` */
  keyId?: Buffer

  /** Indicates whether the request is fulfillable (unfulfillable requests are passed to the handler in case they carry useful application data) */
  isFulfillable: boolean

  /** Amount that arrived */
  amount: BigNumber

  /** Data sent by the sender */
  data: Buffer

  /** Fulfill the packet, and optionally send some data back to the sender */
  accept: (responseData?: Buffer, socketInfo?: SocketInfo, socketCtrl?: SocketCtrlMessage) => void

  /** Reject the packet, and optionally send some data back to the sender */
  reject: (responseData?: Buffer, socketInfo?: SocketInfo, socketCtrl?: SocketCtrlMessage) => void

  socketInfo?: SocketInfo

  socketCtrl?: SocketCtrlMessage
}

export interface PaymentReceived {
  id: Buffer
  receivedAmount: string
  expectedAmount: string
  chunksFulfilled: number
}

/**
 * Params for instantiating a Receiver using the [`createReceiver`]{@link createReceiver} function.
 */
export interface ReceiverOpts {
  /** Ledger Plugin */
  plugin: PluginV2
  /** Callback for handling incoming packets */
  requestHandler?: RequestHandler
  /** Cryptographic seed that will be used to generate shared secrets for multiple senders */
  secret?: Buffer
}

/**
 * PSK2 Receiver class that listens for and accepts incoming payments.
 *
 * The same Receiver may be used for accepting single-chunk payments, streaming payments, and chunked payments.
 *
 * It is recommended to use the [`createReceiver`]{@link createReceiver} function to instantiate Receivers.
 */
export class Receiver {
  
  //Constructor params
  private _plugin: PluginV2
  private _secret: Buffer
  private _requestHandler: RequestHandler

  //Set during connect
  private _baseAddress: string
  private _connected: boolean
  private _connectionSpecificRequestHandlers: { [connectionId: string]: { sharedSecret: Buffer, requestHandler: RequestHandler } }

  constructor (plugin: PluginV2, secret: Buffer) {
    this._plugin = plugin
    assert(secret.length >= 32, 'secret must be at least 32 bytes')
    this._secret = secret
    this._baseAddress = ''
    this._connected = false
    this._requestHandler = Receiver.DefaultRequestHandler
    this._connectionSpecificRequestHandlers = {}
  }

  /**
   * Fetch the receiver's ILP address using [ILDCP](https://github.com/interledgerjs/ilp-protocol-ildcp) and listen for incoming payments.
   */
  async connect (): Promise<void> {
    debug('connect called')
    await this._plugin.connect()
    // TODO refetch address if we're connected for long enough
    this._baseAddress = (await ILDCP.fetch(this._plugin.sendData.bind(this._plugin))).clientAddress
    this._plugin.registerDataHandler(this._handleData)
    this._connected = true
    debug('connected')
  }

  /**
   * Stop listening for incoming payments.
   */
  async disconnect (): Promise<void> {
    debug('disconnect called')
    this._connected = false
    this._plugin.deregisterDataHandler()
    await this._plugin.disconnect()
    debug('disconnected')
  }

  /**
   * Check if the receiver is currently listening for incoming payments.
   */
  isConnected (): boolean {
    this._connected = this._connected && this._plugin.isConnected()
    return this._connected
  }

  /**
   * Register a callback that will be called each time a packet is received.
   *
   * The user must call `accept` to make the Receiver fulfill the packet.
   */
  registerRequestHandler (handler: RequestHandler): void {
    if(this._requestHandler != Receiver.DefaultRequestHandler) {
      throw new Error(`A request handler is already registered. Use 'deregisterRequestHandler() to remove it first.'`)
    }

    debug('registered request handler')
    this._requestHandler = handler
  }

  /**
   * Remove the handler callback.
   */
  deregisterRequestHandler (): void {
    this._requestHandler = Receiver.DefaultRequestHandler
  }

  /**
   * Generate a unique ILP address and shared secret to give to a sender.
   *
   * The Receiver must be connected before this method can be called.
   *
   * **Note:** A single shared secret MUST NOT be given to more than one sender.
   *
   * @param keyId Additional segment that will be appended to the destinationAccount and can be used to correlate payments. This is authenticated but **unencrypted** so the entire Interledger will be able to see this value.
   */
  generateAddressAndSecret (keyId?: Buffer): { destinationAccount: string, sharedSecret: Buffer } {
    assert(this._connected, 'Receiver must be connected')
    const token = crypto.randomBytes(TOKEN_LENGTH)
    const keygen = (keyId ? Buffer.concat([token, keyId]) : token)
    const sharedSecret = generateSharedSecret(this._secret, keygen)
    return {
      sharedSecret,
      destinationAccount: `${this._baseAddress}.${base64url(keygen)}`
    }
  }

  /**
   * Register a `RequestHandler` for a specific `sharedSecret`.
   * This will be called instead of the normal `requestHandler` when requests come in for the `destinationAccount` returned by this function.
   *
   * This is especially useful for bidirectional protocols built on top of PSK2 in which both sides want to use the same sharedSecret.
   *
   * @param sharedSecret Secret to use for decrypting data and generating fulfillments
   * @param handler Callback that will be called when a request comes in for the `destinationAccount` returned by this function
   */
  registerRequestHandlerForSecret (sharedSecret: Buffer, handler: RequestHandler): { destinationAccount: string, sharedSecret: Buffer } {

    const generator = hmac(this._secret, Buffer.from(PSK_ADDRESS_FROM_SECRET_STRING, 'utf8'))
    const addressSuffix = base64url(hmac(generator, sharedSecret).slice(0, TOKEN_LENGTH))

    if (this._connectionSpecificRequestHandlers[addressSuffix]) {
      throw new Error('RequestHandler already registered for that sharedSecret. The old handler must be deregistered first before another one is added')
    }

    this._connectionSpecificRequestHandlers[addressSuffix] = {
      sharedSecret,
      requestHandler: handler
    }
    debug(`added specific request handler for address suffix: ${addressSuffix}`)

    return {
      sharedSecret,
      destinationAccount: `${this._baseAddress}.${addressSuffix}`
    }
  }

  /**
   * Remove the requestHandler for a specific sharedSecret. Does nothing if there is no handler registered
   */
  deregisterRequestHandlerForSecret (sharedSecret: Buffer): void {
    const generator = hmac(this._secret, Buffer.from(PSK_ADDRESS_FROM_SECRET_STRING, 'utf8'))
    const addressSuffix = base64url(hmac(generator, sharedSecret).slice(0, TOKEN_LENGTH))

    if (this._connectionSpecificRequestHandlers[addressSuffix]) {
      delete this._connectionSpecificRequestHandlers[addressSuffix]
      debug(`removed specific request handler for address suffix: ${addressSuffix}`)
    } else {
      debug(`tried to remove specific request handler for address suffix: ${addressSuffix}, but there was no handler registerd`)
    }
  }

  static DefaultRequestHandler = async (params: RequestHandlerParams): Promise<void> => {
    debug(`Receiver has no handler registered, rejecting request of amount: ${params.amount} with data: ${params.data.toString('hex')}`)
    return params.reject(Buffer.alloc(0))
  }

  private reject (code: string, message?: string, data?: Buffer) {
    return IlpPacket.serializeIlpReject({
      code,
      message: message || '',
      data: data || Buffer.alloc(0),
      triggeredBy: this._baseAddress
    })
  }

  // This is an arrow function so we don't need to use bind when setting it on the plugin
  private _handleData = async (data: Buffer): Promise<Buffer> => {
    let prepare: IlpPacket.IlpPrepare
    let sharedSecret: Buffer
    let requestHandler: RequestHandler
    let keyId = undefined

    try {
      prepare = IlpPacket.deserializeIlpPrepare(data)
    } catch (err) {
      debug('error parsing incoming prepare:', err)
      return this.reject('F06', 'Packet is not an IlpPrepare')
    }

    const localParts = prepare.destination.replace(this._baseAddress + '.', '').split('.')
    if (localParts.length === 0) {
      return this.reject('F02', 'Packet is not for this receiver')
    }
    if (this._connectionSpecificRequestHandlers[localParts[0]]) {
      requestHandler = this._connectionSpecificRequestHandlers[localParts[0]].requestHandler
      sharedSecret = this._connectionSpecificRequestHandlers[localParts[0]].sharedSecret
    } else {
      const keygen = Buffer.from(localParts[0], 'base64')
      if (keygen.length > TOKEN_LENGTH) {
        keyId = keygen.slice(TOKEN_LENGTH)
      }
      sharedSecret = generateSharedSecret(this._secret, keygen)
      requestHandler = this._requestHandler.bind(this)
    }

    let packet
    try {
      packet = encoding.deserializePskPacket(sharedSecret, prepare.data)
    } catch (err) {
      debug('unable to parse PSK packet, either because it is an unrecognized type or because the data has been tampered with:', JSON.stringify(prepare), err && err.message)
      // TODO should this be a different error?
      return this.reject('F06', 'Unable to parse data')
    }
    if (packet.type !== encoding.Type.Request) {
      // TODO should this be a different error?
      debug('packet is not a PSK Request (should be type 4):', packet)
      return this.reject('F06', 'Unexpected packet type')
    }
    packet = packet as encoding.PskPacket

    let isFulfillable = false
    let errorCode = 'F99'
    let errorMessage = ''

    // Check if we can regenerate the correct fulfillment
    let fulfillment: Buffer
    try {
      fulfillment = dataToFulfillment(sharedSecret, prepare.data)
      const generatedCondition = fulfillmentToCondition(fulfillment)
      if (generatedCondition.equals(prepare.executionCondition)) {
        isFulfillable = true
      } else {
        isFulfillable = false
        errorCode = 'F05'
        errorMessage = 'Condition generated does not match prepare'
        debug(`condition generated does not match. expected: ${prepare.executionCondition.toString('base64')}, actual: ${generatedCondition.toString('base64')}`)

      }
    } catch (err) {
      isFulfillable = false
      errorCode = 'F05'
      errorMessage = 'Condition does not match prepare'
      debug('unable to generate fulfillment from data:', err)
    }

    // Check if the amount we received is enough
    if (packet.amount.isGreaterThan(prepare.amount)) {
      isFulfillable = false
      debug(`incoming transfer amount too low. actual: ${prepare.amount}, expected: ${packet.amount}`)
    }

    const { fulfill, responseData, responseSocketInfo, responseSocketCtrl } = await callRequestHandler(requestHandler, isFulfillable, packet.requestId, prepare.amount, 
      packet.data, keyId, packet.socketInfo, packet.socketCtrl)
    if (fulfill && isFulfillable) {
      return IlpPacket.serializeIlpFulfill({
        /* tslint:disable-next-line:no-unnecessary-type-assertion */
        fulfillment: fulfillment!,
        data: encoding.serializePskPacket(sharedSecret, {
          type: encoding.Type.Response,
          requestId: packet.requestId,
          amount: new BigNumber(prepare.amount),
          data: responseData,
          socketInfo: responseSocketInfo,
          socketCtrl: responseSocketCtrl
        }, undefined)
      })
    } else {
      return this.reject(errorCode, errorMessage, encoding.serializePskPacket(sharedSecret, {
        type: encoding.Type.Error,
        requestId: packet.requestId,
        amount: new BigNumber(prepare.amount),
        data: responseData,
        socketInfo: responseSocketInfo,
        socketCtrl: responseSocketCtrl
  }, undefined))
    }
  }
}

/**
 * Convenience function for instantiating and connecting a PSK2 [Receiver]{@link Receiver}.
 *
 * @example <caption>Creating a Receiver</caption>
 * ```typescript
 * import { createReceiver } from 'ilp-protocol-psk2'
 * const receiver = await createReceiver({
 *   plugin: myLedgerPlugin,
 *   requestHandler: async (params) => {
 *     params.accept()
 *     console.log(`Got payment for: ${params.amount}`)
 *   }
 * })
 *
 * const { destinationAccount, sharedSecret } = receiver.generateAddressAndSecret()
 * // Give these two values to a sender to enable them to send payments to this Receiver
 * ```
 */
export async function createReceiver (opts: ReceiverOpts): Promise<Receiver> {
  const {
    plugin,
    requestHandler,
    secret = crypto.randomBytes(32)
  } = opts
  const receiver = new Receiver(plugin, secret)
  if (requestHandler) {
    receiver.registerRequestHandler(requestHandler)
  }
  await receiver.connect()
  return receiver
}

async function callRequestHandler (requestHandler: RequestHandler, isFulfillable: boolean, requestId: number, amount: string, data: Buffer, 
  keyId?: Buffer, socketInfo?: SocketInfo, socketCtrl?: SocketCtrlMessage): 
Promise<{ fulfill: boolean, responseData: Buffer, responseSocketInfo?: SocketInfo, responseSocketCtrl?: SocketCtrlMessage}> {
  let fulfill = false
  let finalized = false
  let responseData = Buffer.alloc(0)
  let responseSocketInfo : SocketInfo | undefined = undefined
  let responseSocketCtrl : SocketCtrlMessage | undefined = undefined

  // This promise resolves when the user has either accepted or rejected the payment
  await new Promise(async (resolve, reject) => {
    // Reject the payment if:
    // a) the user explicity calls reject
    // b) if they don't call accept
    // c) if there is an error thrown in the request handler
    try {
      await requestHandler({
        isFulfillable,
        keyId,
        amount: (isFulfillable ? new BigNumber(amount) : new BigNumber(0)),
        data,
        accept: (userResponse = Buffer.alloc(0), userSocketInfo?: SocketInfo, userSocketCtrl? : SocketCtrlMessage) => {
          if (finalized) {
            throw new Error(`Packet was already ${fulfill ? 'fulfilled' : 'rejected'}`)
          }
          if (!isFulfillable) {
            throw new Error('Packet is unfulfillable')
          }
          finalized = true
          fulfill = true
          responseData = userResponse
          responseSocketInfo = userSocketInfo
          responseSocketCtrl = userSocketCtrl
          debug(`user accepted packet with requestId ${requestId}${keyId ? ' for keyId: ' + base64url(keyId) : ''}`)
          resolve()
        },
        reject: (userResponse = Buffer.alloc(0), userSocketInfo?: SocketInfo, userSocketCtrl? : SocketCtrlMessage) => {
          if (finalized) {
            throw new Error(`Packet was already ${fulfill ? 'fulfilled' : 'rejected'}`)
          }
          finalized = true
          responseData = userResponse
          responseSocketInfo = userSocketInfo
          responseSocketCtrl = userSocketCtrl
          debug(`user rejected packet with requestId: ${requestId}${keyId ? ' for keyId: ' + base64url(keyId) : ''}`)
          resolve()
        },
        socketInfo,
        socketCtrl
      })
    } catch (err) {
      debug('error in requestHandler, going to reject the packet:', err)
    }
    if (!finalized) {
      finalized = true
      debug('requestHandler returned without user calling accept or reject, rejecting the packet now')
    }
    resolve()
  })

  return {
    fulfill,
    responseData,
    responseSocketInfo,
    responseSocketCtrl
}
}

function generateSharedSecret (secret: Buffer, token: Buffer): Buffer {
  const sharedSecretGenerator = hmac(secret, Buffer.from(PSK_GENERATION_STRING, 'utf8'))
  return hmac(sharedSecretGenerator, token).slice(0, SHARED_SECRET_LENGTH)
}

function hmac (key: Buffer, message: Buffer): Buffer {
  const h = crypto.createHmac('sha256', key)
  h.update(message)
  return h.digest()
}

function base64url (buf: Buffer): string {
  return buf.toString('base64')
    .replace(/=+$/, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
}
