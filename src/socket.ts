import * as Debug from 'debug'
import BigNumber from 'bignumber.js'
import { randomBytes } from 'crypto'
import {SimpleEventDispatcher, EventDispatcher, IEvent, ISimpleEvent } from "strongly-typed-events";
import * as oer from 'oer-utils'
import * as Long from 'long'
import { Buffer } from 'buffer';
import { PluginV2 } from 'ilp-compat-plugin'
import {Receiver, RequestHandlerParams} from './receiver'
import {sendRequest, PskResponse, PskError} from './sender'
import { isPskResponse } from './index';

const ZERO = new BigNumber(0)
const ONE = new BigNumber(1)
const MAX_UINT64 = new BigNumber('18446744073709551615')
const QUOTE_AMOUNT = new BigNumber('1000')
const DEFAULT_STABILIZED_TIMEOUT = 60000

export enum PaymentSocketState {
  Created = 1,
  Bound = 2,
  Listening = 4,
  Connected = 8,
  Closed = 16
}

export enum SocketCtrlBits {
  IsAutoIncrementing = 1,
  EnableAutoIncrementing = 2,
  TargetDeltaIsNegative = 4,
  ChangeAddress = 8
}

export interface SocketCtrlMessage {
  enableAutoIncrementingTarget: boolean,
  targetDelta: BigNumber,
}

export interface SocketInfo {
  address: string,
  balance: BigNumber,
  targetBalance: BigNumber,
  sendingRate: BigNumber,
  isAutoIncrementingTarget: boolean,
  mtu: BigNumber,
}

export interface SocketCtrlMessageHandler {
  (message: SocketCtrlMessage) : SocketCtrlMessage
}

export interface PaymentSocketOpts {
  plugin: PluginV2,
  ctrlMessageHandler?: SocketCtrlMessageHandler,
  serverSocketParams?: {
    incomingConnectionRequest: RequestHandlerParams
    connectionRequestCallback: (value?: any) => void
    receiver: Receiver
  }
}

export interface SocketConnectParams {
    initialBalance: BigNumber
    initialTargetBalance: BigNumber
    estimatedCurrentRate: BigNumber
    isAutoIncrementingTarget: boolean
    requestedRemoteTarget: BigNumber
    requestAutoIncrementingTargetAtRemote: boolean
}

export class PaymentSocket {

  //Set in constructor
  private _plugin: PluginV2
  private _ctrlMessageHandler: SocketCtrlMessageHandler
  private _incomingConnectionRequest : RequestHandlerParams //Passed from server when creating a server socket
  private _incomingConnectionRequestCallback : (value?: any) => void //Passed from server when creating a server socket

  //Set during connect
  private _sharedSecret: Buffer
  private _receiver: Receiver

  //State info
  private _state: PaymentSocketState
  private _localInfo: SocketInfo
  private _remoteInfo: SocketInfo
  private _requestRemoteTarget: BigNumber
  private _requestRemoteToSetAutoIncrementingTarget: boolean

  //Counters
  private _totalSent: BigNumber
  private _totalDelivered: BigNumber

  //Events
  private _onConnected = new SimpleEventDispatcher<PaymentSocket>();
  private _onClosed = new SimpleEventDispatcher<PaymentSocket>();
  private _onPaymentReceived = new EventDispatcher<PaymentSocket, BigNumber>();
  private _onPaymentSent = new EventDispatcher<PaymentSocket, BigNumber>();
  private _onLocalInfoChanged = new EventDispatcher<PaymentSocket, SocketInfo>();
  private _onRemoteInfoChanged = new EventDispatcher<PaymentSocket, SocketInfo>();
  private _onChangeRequestApplied = new EventDispatcher<PaymentSocket, SocketCtrlMessage>();
  private _onChangeRequestRejected = new EventDispatcher<PaymentSocket, SocketCtrlMessage>();

  private _debug = Debug(`ilp-protocol-psk2:socket`)

  // TODO expose the number of chunks sent/received or fulfilled/rejected?
  constructor (options: PaymentSocketOpts) {

    this._plugin = options.plugin
    this._ctrlMessageHandler = options.ctrlMessageHandler || PaymentSocket.RejectAllCtrlMessageHandler
    
    this._requestRemoteTarget = ZERO
    this._requestRemoteToSetAutoIncrementingTarget = false

    this._localInfo = {
      address: "",
      balance: ZERO,
      targetBalance: ZERO,
      sendingRate: ONE,
      isAutoIncrementingTarget: true,
      mtu: new BigNumber(100) 
      //TODO Better way to set initial MTU
    }

    this._remoteInfo = {
      address: "",
      balance: ZERO,
      targetBalance: ZERO,
      sendingRate: ONE,
      isAutoIncrementingTarget: true,
      mtu: new BigNumber(100) 
      //TODO Better way to set initial MTU
    }

    this._state = PaymentSocketState.Created

    this._totalSent = ZERO
    this._totalDelivered = ZERO

    //Created by a server from an incoming connection request so we can bind
    if(options.serverSocketParams) {

      this._receiver = options.serverSocketParams.receiver
      this._incomingConnectionRequest = options.serverSocketParams.incomingConnectionRequest
      this._incomingConnectionRequestCallback = options.serverSocketParams.connectionRequestCallback

      const {destinationAccount, sharedSecret} = this._receiver.generateAddressAndSecret(this._incomingConnectionRequest.keyId)
      this._receiver.registerRequestHandlerForSecret(sharedSecret, this._handleIncomingRequest)
      
      this._sharedSecret = sharedSecret
      this._localInfo.address = destinationAccount

      this._state = PaymentSocketState.Bound

      this._debug(`new server socket created and bound to address: ${destinationAccount}.`)

    } else {
      this._debug(`new client socket created.`)
    }

  }

  get local(): SocketInfo {
    return this._localInfo
  }

  get remote(): SocketInfo {
    return this._remoteInfo
  }

  get sharedSecret (): Buffer {
    return this._sharedSecret
  }

  get totalSent (): string {
    return this._totalSent.toString()
  }

  get totalDelivered (): string {
    return this._totalDelivered.toString()
  }

  //Events

  get onConnected() : ISimpleEvent<PaymentSocket> {
    return this._onConnected.asEvent();
  }

  get onLocalInfoChanged() : IEvent<PaymentSocket, SocketInfo> {
    return this._onLocalInfoChanged.asEvent();
  }

  get onRemoteInfoChanged() : IEvent<PaymentSocket, SocketInfo> {
    return this._onRemoteInfoChanged.asEvent();
  }

  get onPaymentReceived() : IEvent<PaymentSocket, BigNumber> {
    return this._onPaymentReceived.asEvent();
  }

  get onPaymentSent() : IEvent<PaymentSocket, BigNumber> {
    return this._onPaymentSent.asEvent();
  }

  /**
   * Bind the socket to a receiver and get a local address for the given secret (only for client sockets)
   * 
   * @param secret the secret that this socket is bound to. This determines the local address of the socket
   */
  async bind(secret: Buffer) : Promise<void> {

    this._assertInState(PaymentSocketState.Created)

    //Connect Receiver and get local address
    this._receiver = new Receiver(this._plugin, secret)
    await this._receiver.connect()
    
    const {destinationAccount, sharedSecret} = this._receiver.registerRequestHandlerForSecret(secret, this._handleIncomingRequest)
    this._localInfo.address = destinationAccount
    this._sharedSecret = sharedSecret

    this._state = PaymentSocketState.Bound
    this._debug(`client socket bound to local address: ${destinationAccount}`)
  }

  /**
   * Request a new client connection.
   * 
   * - Send a probing quote payment to establish rate. 
   * - Send current limits and requested limits in payment.
   * - Process requested limit changes in response.
   * 
   * @param params Connection parameters
   * @param remoteAddress The address of the server (undefined when returned by ['server.accept(SocketCtrlMessageHandler, Buffer)']{@link server.accept(SocketCtrlMessageHandler, Buffer)})
   * @returns the address of the local socket after connecting
   */
  async connect(params: SocketConnectParams, remoteAddress?: string) : Promise<void> {

    this._assertInState(PaymentSocketState.Bound)

    this._localInfo.balance = params.initialBalance
    this._localInfo.targetBalance = params.initialTargetBalance
    this._localInfo.sendingRate = params.estimatedCurrentRate || ONE
    this._localInfo.isAutoIncrementingTarget = params.isAutoIncrementingTarget,
    this._localInfo.mtu = new BigNumber(100), //TODO Better way to establish MTU
    this._debug(`initial local state: ${JSON.stringify(this._localInfo)}`)

    this._requestRemoteTarget = params.requestedRemoteTarget
    this._requestRemoteToSetAutoIncrementingTarget = params.requestAutoIncrementingTargetAtRemote
    this._debug(`requesting remote to ${this._requestRemoteTarget.isNegative() ? 'decrease' : 'increase'} target by ${this._requestRemoteTarget}` 
      + ` ${this._requestRemoteToSetAutoIncrementingTarget ? ' and enable auto-incrementing' : ''}.`)

    if(remoteAddress) {

      this._remoteInfo.address = remoteAddress
      this._debug(`client connecting to: ${remoteAddress}`)

    } else {
      if(!this._incomingConnectionRequest) {
        throw new Error('A remoteAddress must be provided unless this socket is created by a server as a result of an incoming connection request')
      }

      this._debug(`server accepting connection from: ${this._incomingConnectionRequest.socketInfo!.address}`)

      this._handleRemoteInfo(this._incomingConnectionRequest.socketInfo!)
      this._handleCtrlMessage(this._incomingConnectionRequest.socketCtrl!)
      
      this._incomingConnectionRequest.accept(Buffer.alloc(0), this._localInfo, this._getNextCtrlMessage())
      this._incomingConnectionRequestCallback()
    }


    //Send connect message (an unfulfillable payment with the socket data)
    const response = await this._sendRequest(QUOTE_AMOUNT, Buffer.alloc(0), true)

    if(!response.socketCtrl || !response.socketInfo) {
      throw new Error(`Response contains no socket info. Unable to create a connection: ${JSON.stringify(response)}`)
    }

    this._onConnected.dispatchAsync(this)

    //Update local rate
    //TODO Event?
    this._localInfo.sendingRate = response.destinationAmount.dividedBy(QUOTE_AMOUNT)

    this._handleRemoteInfo(response.socketInfo)
    this._handleCtrlMessage(response.socketCtrl)

    this._sendNext()

  }

  sendPayment (maxToSendFromLocal: BigNumber.Value, amountToReceiveAtRemote?: BigNumber.Value) : void {

    if (this._localInfo.targetBalance.isGreaterThan(ZERO)) {
      if (this._localInfo.targetBalance.isGreaterThan(maxToSendFromLocal)) {
        this._localInfo.targetBalance = this._localInfo.targetBalance.minus(maxToSendFromLocal)
      } else {
        const balanceIncrease = new BigNumber(maxToSendFromLocal).minus(this._localInfo.targetBalance)
        this._localInfo.targetBalance = ZERO
        this._localInfo.balance = this._localInfo.balance.plus(balanceIncrease)
        //TODO Emit balance increased event
      }
    } else {
      this._localInfo.balance = this._localInfo.balance.plus(maxToSendFromLocal)
      //TODO Emit balance increased event
    }

    if(amountToReceiveAtRemote) {
      this._requestRemoteTarget = this._requestRemoteTarget.plus(amountToReceiveAtRemote)
    } else {
      this._requestRemoteToSetAutoIncrementingTarget = true
    }

   this._sendNext()

  }

  requestPayment (minToReceiveAtLocal: BigNumber.Value, amountToSendFromRemote?: BigNumber.Value) : void {
    
    this._localInfo.targetBalance = this._localInfo.targetBalance.plus(minToReceiveAtLocal)
    if(amountToSendFromRemote) {
      this._requestRemoteTarget = this._requestRemoteTarget.minus(amountToSendFromRemote)
    }

    this._sendNext()
  }

  async close () : Promise<void> {
    this._debug(`closing payment socket`)
    this._state = PaymentSocketState.Closed
    
    await this._receiver.disconnect()
    
    this._onClosed.dispatchAsync(this)
  }

  private _sendRequest(amount: BigNumber, data: Buffer, useUnfulfillableCondition?: boolean) : Promise<PskResponse | PskError> {
    return sendRequest(this._plugin, {
      destinationAccount: this._remoteInfo.address,
      sharedSecret: this._sharedSecret,
      sourceAmount: amount,
      data: data,
      useUnfulfillableCondition,
      socketInfo: this._localInfo,
      socketCtrl: this._getNextCtrlMessage()
    })
  }

  private _assertInState(states: number) : void {
    if((this._state & states) == 0) {
      throw new Error(`Invalid state: ${this._state}`)
    }
  }

  //TODO Implement some congestion control
  private _calculateNextChunkAmount(max: BigNumber) {
    if(max.isLessThanOrEqualTo(this._localInfo.mtu)) {
      return max
    }
    return this._localInfo.mtu
  }

  private _handleIncomingRequest = async (request: RequestHandlerParams) : Promise<void> => {

    switch(this._state) {

      case PaymentSocketState.Closed:
        this._debug('Rejecting request because the socket is closed')
        return request.reject() //TODO Appropriate error

      case PaymentSocketState.Connected:

        const openToReceive = (this._localInfo.balance.isLessThan(this._localInfo.targetBalance)) || this._localInfo.isAutoIncrementingTarget

        if(!request.socketInfo || ! request.socketCtrl) {
          this._debug(`Rejecting request as it contains no socket data.`)
          request.reject(Buffer.alloc(0), this._localInfo, this._getNextCtrlMessage())
          return
        }

        this._handleRemoteInfo(request.socketInfo)
        this._handleCtrlMessage(request.socketCtrl)

        if (!this._localInfo.isAutoIncrementingTarget && request.amount.plus(this._localInfo.balance).isGreaterThan(this._localInfo.targetBalance)) {
          this._debug(`Rejecting request for ${request.amount} because balance is already: ` +
            `${this._localInfo.balance} and target is only: ${this._localInfo.targetBalance}. (Auto-incrementing target is disabled)`)

          request.reject(Buffer.alloc(0), this._localInfo, this._getNextCtrlMessage())
          return
        }

        //Update balance
        this._localInfo.balance = this._localInfo.balance.plus(request.amount)

        request.accept(Buffer.alloc(0), this._localInfo, this._getNextCtrlMessage())

        if (request.amount.isGreaterThan(0)) {
          this._onPaymentReceived.dispatchAsync(this, request.amount)
        }

        this._sendNext()
        
        return  
    }
  }

  private _getNextCtrlMessage() : SocketCtrlMessage {
    const socketCtrl = {
      enableAutoIncrementingTarget: this._requestRemoteToSetAutoIncrementingTarget,
      targetDelta: this._requestRemoteTarget,
    }

    //Reset Ctrl Messages
    this._requestRemoteToSetAutoIncrementingTarget = false
    this._requestRemoteTarget = ZERO

    return socketCtrl
  }

  private _handleRemoteInfo(info: SocketInfo) : void {

    if((this._remoteInfo.address == info.address) &&
      this._remoteInfo.balance == info.balance &&
      this._remoteInfo.sendingRate == info.sendingRate &&
      this._remoteInfo.isAutoIncrementingTarget == info.isAutoIncrementingTarget &&
      this._remoteInfo.targetBalance == info.targetBalance &&
      this._remoteInfo.mtu == info.mtu
    ) {
        //No changes
        this._debug(`no changes in remote info received`)
        return
    } else {
      this._onRemoteInfoChanged.dispatchAsync(this, info)
      
      //Update local view of remote state
      this._remoteInfo.address = info.address
      this._remoteInfo.balance = info.balance
      this._remoteInfo.sendingRate = info.sendingRate
      this._remoteInfo.targetBalance = info.targetBalance
      this._remoteInfo.isAutoIncrementingTarget = info.isAutoIncrementingTarget
      this._remoteInfo.mtu = info.mtu
      this._debug(`new remote info ${JSON.stringify(this._remoteInfo)}`)

    }

  }

  private _handleCtrlMessage(ctrlMessage: SocketCtrlMessage) : void {

      //Are there changes?
      if(ctrlMessage.targetDelta.isEqualTo(ZERO) && ctrlMessage.enableAutoIncrementingTarget) {
        this._debug(`no changes in ctrl message`)
        return
      }

      const changesToApply = this._ctrlMessageHandler(ctrlMessage)

      //Handler stripped all the changes
      if(ctrlMessage.targetDelta.isEqualTo(ZERO) && ctrlMessage.enableAutoIncrementingTarget) {
        this._onChangeRequestRejected.dispatchAsync(this, ctrlMessage)
        this._debug(`all changes in ctrl message rejected by handler`)
        return
      }

      this._localInfo.isAutoIncrementingTarget = (changesToApply.enableAutoIncrementingTarget) ? true : this._localInfo.isAutoIncrementingTarget      
      if(this._localInfo.targetBalance.plus(changesToApply.targetDelta).isNegative()) {
        const balanceIncrease = this._localInfo.targetBalance.plus(changesToApply.targetDelta).absoluteValue()
        this._localInfo.balance = this._localInfo.balance.plus(balanceIncrease)
        this._localInfo.targetBalance = ZERO
        //TODO Emit balance increase event
      } else {
        this._localInfo.targetBalance = this._localInfo.targetBalance.plus(changesToApply.targetDelta)
      }

      this._debug(`ctrl message applied. Balance target delta: ${changesToApply.targetDelta.toString()}` + 
      `${changesToApply.enableAutoIncrementingTarget} ? and auto-incrementing enabled.`)

      this._onChangeRequestApplied.dispatchAsync(this, changesToApply)

      this._sendNext()
  }

  private async _sendNext (): Promise<void> {


    const localAmountAvailableToSend = this._localInfo.balance.minus(this._localInfo.targetBalance)
    const remoteAmountAbleToReceive = this._remoteInfo.targetBalance.minus(this._remoteInfo.balance)

    //Can we send money
    let amountToSend = ZERO
    if(localAmountAvailableToSend.isGreaterThan(ZERO)) {
      if(this._remoteInfo.isAutoIncrementingTarget) {
        amountToSend = this._calculateNextChunkAmount(localAmountAvailableToSend)
      } else if(remoteAmountAbleToReceive.isGreaterThan(ZERO)) {
        //Remote is able to receive
        const localAmountThatRemoteCanReceive = remoteAmountAbleToReceive.dividedBy(this._localInfo.sendingRate)
        amountToSend = this._calculateNextChunkAmount(BigNumber.min(localAmountAvailableToSend, localAmountThatRemoteCanReceive))
      }
    } 

    //Do we have something to send?
    if(this._requestRemoteToSetAutoIncrementingTarget || !this._requestRemoteTarget.isEqualTo(ZERO) || amountToSend.isGreaterThan(ZERO)){

      this._debug(`sending payment for ${amountToSend}`)

      // Send the payment
      let useUnfulfillableCondition = false
      if(amountToSend.isGreaterThan(ZERO)) {
        useUnfulfillableCondition = true
        amountToSend = new BigNumber(1000)
      }
      const response = await this._sendRequest(amountToSend, Buffer.alloc(0), false)

      //Update local rate
      this._localInfo.sendingRate = response.destinationAmount.dividedBy(amountToSend)

      if(!response.socketInfo || ! response.socketCtrl) {
        this._debug(`Response contains no socket data. Closing down the socket.`)
        this.close()
        throw new Error(`Got a response with no socket data.`)
      }

      //Process response socket data
      this._handleRemoteInfo(response.socketInfo)
      this._handleCtrlMessage(response.socketCtrl)


      if (isPskResponse(response) && response.fulfilled) {
        this._totalSent = this._totalSent.plus(amountToSend)
        this._totalDelivered = this._totalDelivered.plus(response.destinationAmount)
        this._localInfo.balance = this._localInfo.balance.minus(amountToSend)
        
        this._onPaymentSent.dispatchAsync(this, amountToSend)

      } else {
        // TODO handle errors
        this._debug(`sending payment failed with code: ${(<PskError>response).code}`)
      }
    }
  }

  static RejectAllCtrlMessageHandler = (socketCtrl: SocketCtrlMessage) : SocketCtrlMessage => {
    return {enableAutoIncrementingTarget: false, targetDelta: ZERO}
  }

  static AllowAllCtrlMessageHandler = (socketCtrl: SocketCtrlMessage) : SocketCtrlMessage => {
    return {
      enableAutoIncrementingTarget: socketCtrl.enableAutoIncrementingTarget, 
      targetDelta: socketCtrl.targetDelta
    }
  }

  static AllowTargetIncreaseAndAutoIncrement = (socketCtrl: SocketCtrlMessage) : SocketCtrlMessage => {
    return {
      enableAutoIncrementingTarget: socketCtrl.enableAutoIncrementingTarget, 
      targetDelta: (socketCtrl.targetDelta.isGreaterThan(ZERO)) ? socketCtrl.targetDelta : ZERO
    }
  }

}