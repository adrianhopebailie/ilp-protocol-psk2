import 'mocha'
import * as sinon from 'sinon'
import { assert } from 'chai'
import * as crypto from 'crypto'
import mock = require('mock-require')
import BigNumber from 'bignumber.js'
import * as IlpPacket from 'ilp-packet'
import MockPlugin from './mocks/plugin'
import { Receiver, createReceiver, PaymentReceived, RequestHandlerParams } from '../src/receiver'
import { sendRequest } from '../src/sender'
import * as encoding from '../src/encoding'
import * as ILDCP from 'ilp-protocol-ildcp'
import { MAX_UINT64, TYPE_PSK2_FULFILLMENT, TYPE_PSK2_REJECT } from '../src/constants'
import * as condition from '../src/condition'

describe('Receiver', function () {
  beforeEach(function () {
    this.plugin = new MockPlugin(0.5)
    this.ildcpStub = sinon.stub(this.plugin, 'sendData')
      .onFirstCall()
      .resolves(ILDCP.serializeIldcpResponse({
        clientAddress: 'test.receiver',
        assetScale: 9,
        assetCode: 'ABC'
      }))
      .callThrough()
    this.receiver = new Receiver(this.plugin, Buffer.alloc(32))
  })

  describe('connect', function () {
    it('should connect the plugin', async function () {
      const spy = sinon.spy(this.plugin, 'connect')
      await this.receiver.connect()
      assert(spy.called)
    })

    it('should use ILDCP to get the receiver ILP address', async function () {
      await this.receiver.connect()
      assert(this.ildcpStub.called)
      // This will throw if it can't parse it
      ILDCP.deserializeIldcpRequest(this.ildcpStub.args[0][0])
    })
  })

  describe('disconnect', function () {
    it('should disconnect the plugin and deregister the data handler', async function () {
      const disconnect = sinon.spy(this.plugin, 'disconnect')
      const deregister = sinon.spy(this.plugin, 'deregisterDataHandler')
      await this.receiver.disconnect()
      assert(disconnect.called)
      assert(deregister.called)
    })
  })

  describe('generateAddressAndSecret', function () {
    it('should throw if the receiver is not connected', function () {
      try {
        this.receiver.generateAddressAndSecret()
      } catch (err) {
        assert.equal(err.message, 'Receiver must be connected')
        return
      }
      assert(false, 'should not get here')
    })

    it('should append the token to the address returned by ILDCP', async function () {
      await this.receiver.connect()
      const { destinationAccount, sharedSecret } = this.receiver.generateAddressAndSecret()
      assert.match(destinationAccount, /^test\.receiver\.[a-zA-Z0-9_-]+$/)
    })

    it('should create a unique shared secret every time it is called', async function () {
      await this.receiver.connect()
      const call1 = this.receiver.generateAddressAndSecret()
      const call2 = this.receiver.generateAddressAndSecret()
      assert.notEqual(call1.destinationAccount, call2.destinationAccount)
      assert.notEqual(call1.sharedSecret, call2.sharedSecret)
    })
  })

  describe('registerRequestHandler', function () {
    it('should not allow you to register two request handlers', async function () {
      this.receiver.registerRequestHandler(() => undefined)
      assert.throws(() => this.receiver.registerRequestHandler(() => undefined))
    })
  })

  describe('registerRequestHandlerForSecret', function () {
    it('should not allow you to register two handlers for the same secret without deregistering one first', async function () {
      const handlerA = (params: RequestHandlerParams) => params.reject()
      const handlerB = (params: RequestHandlerParams) => params.accept()
      const sharedSecret = Buffer.alloc(32)
      this.receiver.registerRequestHandlerForSecret(sharedSecret, handlerA)
      assert.throws(() => this.receiver.registerRequestHandlerForSecret(sharedSecret, handlerB))

      this.receiver.deregisterRequestHandlerForSecret(sharedSecret)

      assert.doesNotThrow(() => this.receiver.registerRequestHandlerForSecret(sharedSecret, handlerB))
    })

    it('should not do anything if you try to deregister a handler for a secret there was no handler for', async function () {
      assert.doesNotThrow(() => this.receiver.deregisterRequestHandlerForSecret(Buffer.alloc(32)))
    })
  })

  describe('handleData', function () {
    beforeEach(async function () {
      await this.receiver.connect()
      this.receiver.deregisterRequestHandler()
    })

    describe('RequestHandler API', function () {
      beforeEach(function () {
        this.receiver.registerRequestHandler(() => undefined)
        const { sharedSecret, destinationAccount } = this.receiver.generateAddressAndSecret()
        this.sharedSecret = sharedSecret
        this.destinationAccount = destinationAccount
        this.pskRequest = {
          type: encoding.Type.Request,
          requestId: 1000,
          amount: new BigNumber(50),
          data: Buffer.from('hello')
        }
        this.pskRequestBuffer = encoding.serializePskPacket(this.sharedSecret, this.pskRequest)
        this.fulfillment = condition.dataToFulfillment(this.sharedSecret, this.pskRequestBuffer)
        this.executionCondition = condition.fulfillmentToCondition(this.fulfillment)
        this.prepare = {
          destination: this.destinationAccount,
          amount: '100',
          data: this.pskRequestBuffer,
          executionCondition: this.executionCondition,
          expiresAt: new Date(Date.now() + 3000)
        }
      })

      describe('invalid packets', function () {
        it('should reject if it gets anything other than an IlpPrepare packet', async function () {
          const response = await this.plugin.sendData(IlpPacket.serializeIlpForwardedPayment({
            account: 'test.receiver',
            data: Buffer.alloc(32)
          }))
          assert(response)
          assert.deepEqual(IlpPacket.deserializeIlpReject(response), {
            code: 'F06',
            message: 'Packet is not an IlpPrepare',
            triggeredBy: 'test.receiver',
            data: Buffer.alloc(0)
          })
        })

        it('should reject if the data has been tampered with', async function () {
          this.prepare.data[10] = ~this.prepare.data[10]
          const response = await this.plugin.sendData(IlpPacket.serializeIlpPrepare(this.prepare))
          assert.deepEqual(IlpPacket.deserializeIlpReject(response), {
            code: 'F06',
            message: 'Unable to parse data',
            triggeredBy: 'test.receiver',
            data: Buffer.alloc(0)
          })
        })

        it('should reject if the PSK packet type is unknown', async function () {
          this.pskRequest.type = 7
          this.pskRequestBuffer = encoding.serializePskPacket(this.sharedSecret, this.pskRequest)
          this.fulfillment = condition.dataToFulfillment(this.sharedSecret, this.pskRequestBuffer)
          this.executionCondition = condition.fulfillmentToCondition(this.fulfillment)
          this.prepare = {
            destination: this.destinationAccount,
            amount: '100',
            data: this.pskRequestBuffer,
            executionCondition: this.executionCondition,
            expiresAt: new Date(Date.now() + 3000)
          }
          const response = await this.plugin.sendData(IlpPacket.serializeIlpPrepare(this.prepare))
          assert.deepEqual(IlpPacket.deserializeIlpReject(response), {
            code: 'F06',
            message: 'Unable to parse data',
            triggeredBy: 'test.receiver',
            data: Buffer.alloc(0)
          })
        })

        it('should reject if the PSK packet is not a request type', async function () {
          this.pskRequest.type = encoding.Type.Response
          this.pskRequestBuffer = encoding.serializePskPacket(this.sharedSecret, this.pskRequest)
          this.fulfillment = condition.dataToFulfillment(this.sharedSecret, this.pskRequestBuffer)
          this.executionCondition = condition.fulfillmentToCondition(this.fulfillment)
          this.prepare = {
            destination: this.destinationAccount,
            amount: '100',
            data: this.pskRequestBuffer,
            executionCondition: this.executionCondition,
            expiresAt: new Date(Date.now() + 3000)
          }
          const response = await this.plugin.sendData(IlpPacket.serializeIlpPrepare(this.prepare))
          assert.deepEqual(IlpPacket.deserializeIlpReject(response), {
            code: 'F06',
            message: 'Unexpected packet type',
            triggeredBy: 'test.receiver',
            data: Buffer.alloc(0)
          })
          this.plugin.hello = 'foo'
        })

        it('should reject if the amount received is less than specified in the PSK Request', async function () {
          // Note: We should be able to use the fixtures attached to this but for some reason this test fails unless these are copied here
          this.pskRequest = {
            type: encoding.Type.Request,
            requestId: 1000,
            amount: new BigNumber(50),
            data: Buffer.from('hello')
          }
          this.pskRequestBuffer = encoding.serializePskPacket(this.sharedSecret, this.pskRequest)
          this.fulfillment = condition.dataToFulfillment(this.sharedSecret, this.pskRequestBuffer)
          this.executionCondition = condition.fulfillmentToCondition(this.fulfillment)
          this.prepare = {
            destination: this.destinationAccount,
            amount: '99',
            data: this.pskRequestBuffer,
            executionCondition: this.executionCondition,
            expiresAt: new Date(Date.now() + 3000)
          }
          const response = await this.plugin.sendData(IlpPacket.serializeIlpPrepare(this.prepare))
          const parsed = IlpPacket.deserializeIlpReject(response)
          assert.equal(parsed.message, '')
          assert.equal(parsed.code, 'F99')
          assert.notEqual(parsed.data.length, 0)
          const pskResponse = encoding.deserializePskPacket(this.sharedSecret, parsed.data)
          assert.equal(pskResponse.requestId, this.pskRequest.requestId)
          assert.equal(pskResponse.amount.toString(10), '49')
        })

        it('should reject (with the PSK rejection packet attached) if it cannot properly generate the fulfillment', async function () {
          // Note: We should be able to use the fixtures attached to this but for some reason this test fails unless these are copied here
          this.pskRequest = {
            type: encoding.Type.Request,
            requestId: 1000,
            amount: new BigNumber(50),
            data: Buffer.from('hello')
          }
          this.pskRequestBuffer = encoding.serializePskPacket(this.sharedSecret, this.pskRequest)
          const executionCondition = Buffer.alloc(32, 0)
          const prepare = {
            destination: this.destinationAccount,
            amount: '100',
            data: this.pskRequestBuffer,
            executionCondition,
            expiresAt: new Date(Date.now() + 3000)
          }
          const response = await this.plugin.sendData(IlpPacket.serializeIlpPrepare(prepare))
          const parsed = IlpPacket.deserializeIlpReject(response)
          assert.equal(parsed.code, 'F05')
          assert.equal(parsed.message, 'Condition generated does not match prepare')
          assert.notEqual(parsed.data.length, 0)
          const pskResponse = encoding.deserializePskPacket(this.sharedSecret, parsed.data)
          assert.equal(pskResponse.amount.toString(10), '50')
        })

        it('should call the requestHandler with the attached data (and an amount of 0) even if it cannot generate the fulfillment', async function () {
          const spy = sinon.spy()
          this.receiver.deregisterRequestHandler()
          this.receiver.registerRequestHandler((params: RequestHandlerParams) => {
            spy(params)
            params.reject(Buffer.from('got it'))
          })
          // Note: We should be able to use the fixtures attached to this but for some reason this test fails unless these are copied here
          this.pskRequest = {
            type: encoding.Type.Request,
            requestId: 1000,
            amount: new BigNumber(50),
            data: Buffer.from('hello')
          }
          this.pskRequestBuffer = encoding.serializePskPacket(this.sharedSecret, this.pskRequest)
          const executionCondition = Buffer.alloc(32, 0)
          const prepare = {
            destination: this.destinationAccount,
            amount: '100',
            data: this.pskRequestBuffer,
            executionCondition,
            expiresAt: new Date(Date.now() + 3000)
          }
          const response = await this.plugin.sendData(IlpPacket.serializeIlpPrepare(prepare))
          assert(spy.called)
          const parsed = IlpPacket.deserializeIlpReject(response)
          assert.notEqual(parsed.data.length, 0)
          const pskResponse = encoding.deserializePskPacket(this.sharedSecret, parsed.data)
          assert.equal(pskResponse.amount.toString(10), '50')
          assert.equal(pskResponse.data.toString(), 'got it')
          assert.strictEqual(spy.args[0][0].isFulfillable, false)
          assert.strictEqual(spy.args[0][0].amount.toString(), '0')
        })

        it('should reject even if the requestHandler calls accpet', async function () {
          const spy = sinon.spy()
          this.receiver.deregisterRequestHandler()
          this.receiver.registerRequestHandler((params: RequestHandlerParams) => {
            spy(params)
            params.accept(Buffer.from('got it'))
          })
          // Note: We should be able to use the fixtures attached to this but for some reason this test fails unless these are copied here
          this.pskRequest = {
            type: encoding.Type.Request,
            requestId: 1000,
            amount: new BigNumber(50),
            data: Buffer.from('hello')
          }
          this.pskRequestBuffer = encoding.serializePskPacket(this.sharedSecret, this.pskRequest)
          const executionCondition = Buffer.alloc(32, 0)
          const prepare = {
            destination: this.destinationAccount,
            amount: '100',
            data: this.pskRequestBuffer,
            executionCondition,
            expiresAt: new Date(Date.now() + 3000)
          }
          const response = await this.plugin.sendData(IlpPacket.serializeIlpPrepare(prepare))
          assert(spy.called)
          const parsed = IlpPacket.deserializeIlpReject(response)
          assert.notEqual(parsed.data.length, 0)
          const pskResponse = encoding.deserializePskPacket(this.sharedSecret, parsed.data)
          assert.equal(pskResponse.amount.toString(10), '50')
          assert.equal(pskResponse.data.toString(), '')
        })
      })

      describe('valid packets', function () {
        beforeEach(function () {
          this.receiver.deregisterRequestHandler()
        })

        it('should accept packets sent by sendRequest', async function () {
          this.receiver.registerRequestHandler((params: RequestHandlerParams) => {
            params.accept(Buffer.from('thanks!'))
          })
          const result = await sendRequest(this.plugin, {
            destinationAccount: this.destinationAccount,
            sharedSecret: this.sharedSecret,
            sourceAmount: '10',
            minDestinationAmount: '1'
          })
          assert.equal(result.fulfilled, true)
          assert.equal(result.data.toString('utf8'), 'thanks!')
          assert.equal(result.destinationAmount.toString(10), '5')
        })

        it('should call the RequestHandler with the amount and data', async function () {
          const spy = sinon.spy()
          this.receiver.registerRequestHandler(spy)
          await this.plugin.sendData(IlpPacket.serializeIlpPrepare(this.prepare))
          assert.equal(spy.args[0][0].amount.toString(10), '50')
          assert.equal(spy.args[0][0].data.toString('utf8'), 'hello')
        })

        it('should reject the packet if the user calls reject', async function () {
          this.receiver.registerRequestHandler((params: RequestHandlerParams) => params.reject(Buffer.from('nope')))
          const response = await this.plugin.sendData(IlpPacket.serializeIlpPrepare(this.prepare))
          const pskResponse = encoding.deserializePskPacket(this.sharedSecret, IlpPacket.deserializeIlpReject(response).data)
          assert.equal(pskResponse.amount.toString(10), '50')
          assert.equal(pskResponse.data.toString('utf8'), 'nope')
        })

        it('should reject the packet if there is an error thrown in the request handler', async function () {
          this.receiver.registerRequestHandler((params: RequestHandlerParams) => { throw new Error('oops') })
          const response = await this.plugin.sendData(IlpPacket.serializeIlpPrepare(this.prepare))
          const pskResponse = encoding.deserializePskPacket(this.sharedSecret, IlpPacket.deserializeIlpReject(response).data)
          assert.equal(pskResponse.amount.toString(10), '50')
          assert.equal(pskResponse.data.toString('utf8'), '')
        })

        it('should reject the packet if the user does not call accept or reject', async function () {
          this.receiver.registerRequestHandler((params: RequestHandlerParams) => { return })
          const response = await this.plugin.sendData(IlpPacket.serializeIlpPrepare(this.prepare))
          const pskResponse = encoding.deserializePskPacket(this.sharedSecret, IlpPacket.deserializeIlpReject(response).data)
          assert.equal(pskResponse.amount.toString(10), '50')
          assert.equal(pskResponse.data.toString('utf8'), '')
        })

        it('should fulfill packets if the user calls accept', async function () {
          this.receiver.registerRequestHandler((params: RequestHandlerParams) => Promise.resolve().then(() => params.accept(Buffer.from('yup'))))
          const response = await this.plugin.sendData(IlpPacket.serializeIlpPrepare(this.prepare))
          const pskResponse = encoding.deserializePskPacket(this.sharedSecret, IlpPacket.deserializeIlpFulfill(response).data)
          assert.equal(pskResponse.requestId, this.pskRequest.requestId)
          assert.equal(pskResponse.amount.toString(10), '50')
          assert.equal(pskResponse.data.toString('utf8'), 'yup')
        })

        it('should throw an error if the user calls accept and reject', async function () {
          let threw = false
          this.receiver.registerRequestHandler((params: RequestHandlerParams) => {
            params.accept(Buffer.from('yup'))
            try {
              params.reject(Buffer.from('nope'))
            } catch (err) {
              threw = true
              throw err
            }
          })
          const response = await this.plugin.sendData(IlpPacket.serializeIlpPrepare(this.prepare))
          const pskResponse = encoding.deserializePskPacket(this.sharedSecret, IlpPacket.deserializeIlpFulfill(response).data)
          assert.equal(pskResponse.data.toString('utf8'), 'yup')
          assert.equal(threw, true)
        })

        it('should be okay with exta segments being appended to the destinationAccount', async function () {
          this.receiver.registerRequestHandler((params: RequestHandlerParams) => Promise.resolve().then(() => params.accept(Buffer.from('yup'))))
          this.prepare.destination = this.prepare.destination + '.some.other.stuff'
          const response = await this.plugin.sendData(IlpPacket.serializeIlpPrepare(this.prepare))
          const pskResponse = encoding.deserializePskPacket(this.sharedSecret, IlpPacket.deserializeIlpFulfill(response).data)
          assert.equal(pskResponse.type, 5)
          assert.equal(pskResponse.amount.toString(10), '50')
          assert.equal(pskResponse.data.toString('utf8'), 'yup')
        })

        it('should pass the keyId to the request handler if one was passed in to createAddressAndSecret', async function () {
          const keyId = Buffer.from('invoice12345')
          const { sharedSecret, destinationAccount } = this.receiver.generateAddressAndSecret(keyId)
          const pskRequest = {
            type: encoding.Type.Request,
            requestId: 1000,
            amount: new BigNumber(50),
            data: Buffer.from('hello')
          }
          const pskRequestBuffer = encoding.serializePskPacket(sharedSecret, pskRequest)
          const fulfillment = condition.dataToFulfillment(sharedSecret, pskRequestBuffer)
          const executionCondition = condition.fulfillmentToCondition(fulfillment)
          const prepare = {
            destination: destinationAccount,
            amount: '100',
            data: pskRequestBuffer,
            executionCondition: executionCondition,
            expiresAt: new Date(Date.now() + 3000)
          }

          this.receiver.registerRequestHandler((params: RequestHandlerParams) => {
            assert.deepEqual(params.keyId, keyId)
            params.accept(Buffer.from('yup', 'utf8'))
          })
          const response = await this.plugin.sendData(IlpPacket.serializeIlpPrepare(prepare))
          const pskResponse = encoding.deserializePskPacket(sharedSecret, IlpPacket.deserializeIlpFulfill(response).data)
          assert.equal(pskResponse.type, 5)
        })

        it('should reject if the keyId is modified', async function () {
          const keyId = Buffer.from('invoice12345')
          const { sharedSecret, destinationAccount } = this.receiver.generateAddressAndSecret(keyId)
          const pskRequest = {
            type: encoding.Type.Request,
            requestId: 1000,
            amount: new BigNumber(50),
            data: Buffer.from('hello')
          }
          const pskRequestBuffer = encoding.serializePskPacket(sharedSecret, pskRequest)
          const fulfillment = condition.dataToFulfillment(sharedSecret, pskRequestBuffer)
          const executionCondition = condition.fulfillmentToCondition(fulfillment)
          const modified = destinationAccount.slice(0, -1) + 'z'
          const prepare = {
            destination: modified,
            amount: '100',
            data: pskRequestBuffer,
            executionCondition: executionCondition,
            expiresAt: new Date(Date.now() + 3000)
          }

          const response = await this.plugin.sendData(IlpPacket.serializeIlpPrepare(prepare))
          const packet = IlpPacket.deserializeIlpReject(response)
          assert.equal(packet.code, 'F06')
          assert.equal(packet.message, 'Unable to parse data')
        })
      })

      describe('Listening with a custom sharedSecret', function () {
        it('should call the given requestHandler instead of the normal one', async function () {
          const normalSpy = sinon.spy()
          const specificSpy = sinon.spy()
          this.receiver.deregisterRequestHandler()
          this.receiver.registerRequestHandler((params: RequestHandlerParams) => {
              params.reject()
            normalSpy()
          })
          const sharedSecret = Buffer.alloc(32, 'FF', 'hex')
          const { destinationAccount } = this.receiver.registerRequestHandlerForSecret(sharedSecret, (params: RequestHandlerParams) => {
            params.accept()
            specificSpy()
          })

          const result = await sendRequest(this.plugin, {
            destinationAccount,
            sharedSecret,
            sourceAmount: '100',
          })

          assert(normalSpy.notCalled)
          assert(specificSpy.called)
        })
      })
    })
  })
})

describe('createReceiver', function () {
  beforeEach(function () {
    this.plugin = new MockPlugin(0.5)
    this.ildcpStub = sinon.stub(this.plugin, 'sendData')
      .onFirstCall()
      .resolves(ILDCP.serializeIldcpResponse({
        clientAddress: 'test.receiver',
        assetScale: 9,
        assetCode: 'ABC'
      }))
  })
})
