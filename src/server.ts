import { randomBytes } from 'crypto'
import * as assert from 'assert'
import * as Debug from 'debug'
import { PaymentSocketState, SocketCtrlMessageHandler, PaymentSocket } from './socket'
import { Receiver, RequestHandlerParams, RequestHandler } from './index'

export class PaymentSocketServer {
  
  private _state: PaymentSocketState
  private _incomingRequestQueue: RequestQueue

  //Set in constructor
  private _plugin: any
  
  //Set during bind
  private _receiver: Receiver

  private _debug = Debug(`ilp-protocol-psk2:server`)

  constructor (plugin: any) {

    //TODO Do we need to check if we have exclusive access to plugin?
    this._plugin = plugin
    this._state = PaymentSocketState.Created
    this._incomingRequestQueue = new RequestQueue()
    
  }

  /**
   * Bind to a new Receiver and ensure it is connected
   */
  async bind() : Promise<void> {

      this._assertInState(PaymentSocketState.Created)
      this._state = PaymentSocketState.Bound

      //TODO Do we need to handle the case where there is already a Receiver attached to this plugin?
      this._receiver = new Receiver(this._plugin, Buffer.alloc(32))

      //TODO Bind to Receiver events like disconnects
      await this._receiver.connect()

      this._debug(`server bound to receiver`)
  }

  /**
   * Return a new address and secret that can be used to connect to this server and puts the socket in the listening state
   * 
   * @param connectionId an optional connectionId which will be encoded into the address given to clients and used as a shared key identifier. This can be provided as a filter when calling ['accept']({@link accept(SocketControlMessageHandler,Buffer)})
   * @returns the ILP Address and shared secret to give clients that will connect to this server
   */
  listen(connectionId?: Buffer) : {destinationAccount: string, sharedSecret: Buffer} {

    if(this._state == PaymentSocketState.Bound) {
      this._receiver.registerRequestHandler(this._handleIncomingRequest)
      this._state = PaymentSocketState.Listening
    }

    this._assertInState(PaymentSocketState.Listening)

    const keyId = connectionId || randomBytes(14)
    const {destinationAccount, sharedSecret} = this._receiver.generateAddressAndSecret(keyId)

    this._debug(`server listening for connections with id: ${keyId.toString('hex')} at address: ${destinationAccount}`)

    return {destinationAccount, sharedSecret}

  }

  /**
   * Listen for the next incoming connection and returns the socket.
   * 
   * @param socketCtrlMessageHandler The handler to use for LimitChangeRequests coming from the client. This will be called with the initial change request in the connect payment.
   */
  async accept(socketCtrlMessageHandler: SocketCtrlMessageHandler, connectionId: Buffer) : Promise<PaymentSocket> {

    this._assertInState(PaymentSocketState.Listening)

    //Wait for next incoming connection
    this._debug(`server waiting to accept incoming connection with id: ${connectionId.toString('hex')}`)

    const {incomingRequest, resultCallback} = await this._incomingRequestQueue.dequeue(connectionId)

    this._debug(`connection received with id: ${incomingRequest.keyId!.toString('hex')} from address: ${incomingRequest.socketInfo!.address}`)

    //Create the socket
    return new PaymentSocket({
      plugin: this._plugin,
      ctrlMessageHandler: socketCtrlMessageHandler,
      serverSocketParams: {
        incomingConnectionRequest: incomingRequest,
        connectionRequestCallback: resultCallback,
        receiver: this._receiver
      }
    })

  }

  /**
   * Close down the server
   */
  async close() : Promise<void> {
    this._debug(`shutting down the server and rejecting queued connection requests.`)
    //Reject queued connection requests
    await this._incomingRequestQueue.empty(Buffer.alloc(0))
    this._state = PaymentSocketState.Closed
  }

  /**
   * Handle incoming requests from the underlying PSK2 receiver
   * 
   * @param incomingRequest incoming request
   */
  private _handleIncomingRequest = (incomingRequest: RequestHandlerParams) : Promise<void> => {

    if(isConnectionRequest(incomingRequest)) {
      return this._incomingRequestQueue.enqueue(incomingRequest)
    } else {
      return Promise.resolve(incomingRequest.reject())
    }

  }

  private _assertInState(states: number) : void {
    if((this._state & states) == 0) {
      throw new Error(`Invalid state: ${this._state}`)
    }
  }

}

interface QueuedConnectionRequest {
  incomingRequest: RequestHandlerParams
  resultCallback: (value?:void) => void
}

//TODO Implement a max backlog
class RequestQueue {

  //TODO Automatically drop connections that time out

  private _promises : Map<string, Promise<QueuedConnectionRequest>>
  private _resultCallbacks : Map<string, (value?:void) => void>
  private _connectionRequests : Map<string, RequestHandlerParams>
  private _connectionRequestHandlers : Map<string, (value?:QueuedConnectionRequest) => void>
  private _connectionRequestResults : Map<string, Promise<any>>

  private _closing : boolean

  constructor() {
    this._promises = new Map<string, Promise<QueuedConnectionRequest>>()
    this._resultCallbacks = new Map<string, (value?:void) => void>()
    this._connectionRequests = new Map<string, RequestHandlerParams>()
    this._connectionRequestHandlers = new Map<string, (value?:QueuedConnectionRequest) => void>()
    this._connectionRequestResults = new Map<string, Promise<any>>()

    this._closing = false
  }

  enqueue(incomingRequest: RequestHandlerParams) : Promise<any> {
    
    if(this._closing) {
      throw new Error(`The queue is closing no more requests can be added.`)
    }

    if(!incomingRequest.keyId) {
      throw new Error("Can't enqueue requests without a connection id")
    }
    
    const connectionIdString = incomingRequest.keyId.toString('hex')

    if (this._connectionRequestHandlers.has(connectionIdString)) {

      //We already have a listener so pass this request and callback to them
      const connectionRequestHandler = this._connectionRequestHandlers.get(connectionIdString)!
      const resultCallback = this._resultCallbacks.get(connectionIdString)!
      const result = this._connectionRequestResults.get(connectionIdString)!

      this._connectionRequestHandlers.delete(connectionIdString)
      this._resultCallbacks.delete(connectionIdString)
      this._connectionRequestResults.delete(connectionIdString)

      connectionRequestHandler({
        incomingRequest,
        resultCallback
      })

      return result

    } else {

      //Add connection to the backlog
      //TODO: Remove if it times out

      this._promises.set(connectionIdString, new Promise<QueuedConnectionRequest>( connectionRequestHandler => {
        this._connectionRequests.set(connectionIdString, incomingRequest)
        this._connectionRequestHandlers.set(connectionIdString, connectionRequestHandler)
      }))

      return new Promise<any>(resultCallback => {
        this._resultCallbacks.set(connectionIdString, resultCallback)
      })
    }


  }

  //TODO: Allow connectionId to be undefined and return next available connection
  dequeue(connectionId: Buffer) : Promise<QueuedConnectionRequest> {
    
    const connectionIdString = connectionId.toString('hex')
    
    if(this._promises.has(connectionIdString)){

      //There are connections in the backlog

      const resultCallback = this._resultCallbacks.get(connectionIdString)!
      const incomingRequest = this._connectionRequests.get(connectionIdString)!
      const connectionRequestHandler = this._connectionRequestHandlers.get(connectionIdString)!
      const promise = this._promises.get(connectionIdString)!

      this._resultCallbacks.delete(connectionIdString)
      this._connectionRequests.delete(connectionIdString)
      this._connectionRequestHandlers.delete(connectionIdString)
      this._promises.delete(connectionIdString)

      connectionRequestHandler({
        incomingRequest,
        resultCallback
      })
  
      return promise

    } else {

      this._connectionRequestResults.set(connectionIdString, new Promise<any>(resultCallback => {     
        this._resultCallbacks.set(connectionIdString, resultCallback)
      }))

      return new Promise<QueuedConnectionRequest>(connectionRequestHandler => {
          this._connectionRequestHandlers.set(connectionIdString, connectionRequestHandler)
      })
    }
  }

  get backlog() : number { // there are connections in the backlog
    return this._promises.size
  }
  
  get isWaiting() : boolean { // waiting for new connections
    return this._connectionRequestHandlers.size > 0
  }

  async empty(rejectData: Buffer | undefined) : Promise<void> {
    this._closing = true

    this._promises.forEach((promise, connectionIdString) => {
      const resultCallback = this._resultCallbacks.get(connectionIdString)!
      this._resultCallbacks.delete(connectionIdString)
      this._promises.delete(connectionIdString)

      promise.then((connectionRequest) =>{
        connectionRequest.incomingRequest.reject()
        connectionRequest.resultCallback()
      })

    });
  }

}

function isConnectionRequest(incomingRequest: RequestHandlerParams) : boolean {
  return incomingRequest.amount.isZero && incomingRequest.keyId !== undefined
}