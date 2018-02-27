import 'mocha'
import * as sinon from 'sinon'
import { assert } from 'chai'
import * as crypto from 'crypto'
import mock = require('mock-require')
import BigNumber from 'bignumber.js'
import * as IlpPacket from 'ilp-packet'
import MockPlugin from './mocks/plugin'
import * as ILDCP from 'ilp-protocol-ildcp'

const SHARED_SECRET = Buffer.alloc(32, 0)
const PAYMENT_ID = Buffer.from('465736837f790f773baafd63828f38b6', 'hex')
const QUOTE_CONDITION = Buffer.from('a4d735b6bd09ebbc971b817384e8fa1d110b0df130c16ac4d326f508040acbc1', 'hex')
const NONCE = Buffer.from('6c93ab43f2b70ac9a0d3844f', 'hex')
const MAX_UINT64 = new BigNumber('18446744073709551615')

mock.stopAll()
mock('crypto', {
  ...crypto,
  randomBytes: function (numBytes: number): Buffer {
    switch (numBytes) {
      case 12:
        return NONCE
      case 16:
        return PAYMENT_ID
      case 32:
        return QUOTE_CONDITION
      default:
        return Buffer.alloc(0)
    }
  }
})
mock.reRequire('../src/encoding')
mock.reRequire('../src/sender')
import * as sender from '../src/sender'
import * as encoding from '../src/encoding'
import { createReceiver, RequestHandlerParams } from '../src/receiver'

describe('Sender', function () {
  beforeEach(function () {
    this.setInterval = setInterval
    this.clearInterval = clearInterval
    this.clock = sinon.useFakeTimers(0)
    this.plugin = new MockPlugin(0.5)
  })

  afterEach(function () {
    this.clock.restore()
  })

  describe('sendRequest', function () {
    it('should send a request that is accepted by the receiver', async function () {
      const receiver = await createReceiver({
        plugin: this.plugin,
        requestHandler: (params: RequestHandlerParams) => { 
          params.accept(Buffer.from('thanks!'))
          return Promise.resolve()
        }
      })
      const { destinationAccount, sharedSecret } = receiver.generateAddressAndSecret()

      const result = await sender.sendRequest(this.plugin, {
        destinationAccount,
        sharedSecret,
        sourceAmount: '10',
        minDestinationAmount: '1'
      })
      assert.equal(result.fulfilled, true)
      assert.equal(result.data.toString('utf8'), 'thanks!')
      assert.equal((result as sender.PskResponse).destinationAmount.toString(10), '5')
    })

    it('should send an unfulfillable request that is rejected by the receiver', async function () {
      const receiver = await createReceiver({
        plugin: this.plugin,
        requestHandler: (params: RequestHandlerParams) => { 
          params.accept(Buffer.from('thanks!'))
          return Promise.resolve()
        }
      })
      const { destinationAccount, sharedSecret } = receiver.generateAddressAndSecret()

      const result = await sender.sendRequest(this.plugin, {
        destinationAccount,
        sharedSecret,
        sourceAmount: '10',
        unfulfillableCondition: Buffer.alloc(32, 0)
      })
      assert.equal(result.fulfilled, false)
      assert.equal(result.data.toString('utf8'), '')
      assert.equal(result.destinationAmount.toString(10), '5')
    })

    it('should return the data the receiver passes back when rejecting the packet', async function () {
      const receiver = await createReceiver({
        plugin: this.plugin,
        requestHandler: (params: RequestHandlerParams) => { 
          params.reject(Buffer.from('nope')) 
          return Promise.resolve()
        }
      })
      const { destinationAccount, sharedSecret } = receiver.generateAddressAndSecret()

      const result = await sender.sendRequest(this.plugin, {
        destinationAccount,
        sharedSecret,
        sourceAmount: '10',
        minDestinationAmount: '1'
      })
      assert.equal(result.fulfilled, false)
      assert.equal(result.data.toString('utf8'), 'nope')
      assert.equal(result.destinationAmount.toString(10), '5')
    })

    it('should be able to use a random unfulfillable condition (for example, for test payments)', async function () {
      const stub = sinon.stub(this.plugin, 'sendData').resolves(IlpPacket.serializeIlpReject({
        code: 'F99',
        message: '',
        triggeredBy: 'test.receiver',
        data: encoding.serializePskPacket(SHARED_SECRET, {
          type: 6,
          amount: new BigNumber(5),
          requestId: 1234,
          data: Buffer.from('hello')
        })
      }))

      const result = await sender.sendRequest(this.plugin, {
        destinationAccount: 'test.receiver',
        sharedSecret: SHARED_SECRET,
        sourceAmount: '10',
        requestId: 1234,
        unfulfillableCondition: QUOTE_CONDITION
      })
      assert(stub.calledOnce)
      assert.deepEqual(IlpPacket.deserializeIlpPrepare(stub.args[0][0]).executionCondition, QUOTE_CONDITION)
      assert.equal(result.fulfilled, false)
      assert.equal(result.destinationAmount.toString(10), '5')
      assert.equal(result.data.toString('utf8'), 'hello')
    })

    it('should be able to use an all-zero unfulfillable condition (for example, for test payments)', async function () {
      const stub = sinon.stub(this.plugin, 'sendData').resolves(IlpPacket.serializeIlpReject({
        code: 'F99',
        message: '',
        triggeredBy: 'test.receiver',
        data: encoding.serializePskPacket(SHARED_SECRET, {
          type: 6,
          amount: new BigNumber(5),
          requestId: 1234,
          data: Buffer.from('hello')
        })
      }))

      const result = await sender.sendRequest(this.plugin, {
        destinationAccount: 'test.receiver',
        sharedSecret: SHARED_SECRET,
        sourceAmount: '10',
        requestId: 1234,
        unfulfillableCondition: Buffer.alloc(32)
      })
      assert(stub.calledOnce)
      assert.deepEqual(IlpPacket.deserializeIlpPrepare(stub.args[0][0]).executionCondition, Buffer.alloc(32))
      assert.equal(result.fulfilled, false)
      assert.equal(result.destinationAmount.toString(10), '5')
      assert.equal(result.data.toString('utf8'), 'hello')
    })

    it('should throw an error if plugin.sendData resolves to something other than an ILP Fulfill or Reject', async function () {
      const stub = sinon.stub(this.plugin, 'sendData').resolves(IlpPacket.serializeIlpRejection({
        code: 'F99',
        message: '',
        triggeredBy: '',
        data: Buffer.alloc(0)
      }))

      try {
        await sender.sendRequest(this.plugin, {
          destinationAccount: 'test.receiver',
          sharedSecret: SHARED_SECRET,
          sourceAmount: '10'
        })
      } catch (err) {
        assert.equal(err.message, 'Unable to parse response from plugin.sendData')
        return
      }
      assert(false, 'should not get here')
    })

    it('should resolve but not return the data or destination amount if the data has been tampered with', async function () {
      const data = encoding.serializePskPacket(SHARED_SECRET, {
        type: 6,
        amount: new BigNumber(5),
        requestId: 1234,
        data: Buffer.from('hello')
      })
      data[10] = ~data[10]
      const stub = sinon.stub(this.plugin, 'sendData').resolves(IlpPacket.serializeIlpReject({
        code: 'F99',
        message: '',
        triggeredBy: 'test.receiver',
        data
      }))

      const result = await sender.sendRequest(this.plugin, {
        destinationAccount: 'test.receiver',
        sharedSecret: SHARED_SECRET,
        sourceAmount: '10',
        requestId: 1234
      }) as sender.PskError
      assert(stub.calledOnce)
      assert.equal(result.fulfilled, false)
      assert.equal(result.code, 'F99')
      assert.equal(result.destinationAmount.toString(10), '0')
      assert.equal(result.data.toString('utf8'), '')
    })

    it('should resolve but not return the data or destination amount if the requestId in the response does not match the outgoing request', async function () {
      const stub = sinon.stub(this.plugin, 'sendData').resolves(IlpPacket.serializeIlpReject({
        code: 'F99',
        message: '',
        triggeredBy: 'test.receiver',
        data: encoding.serializePskPacket(SHARED_SECRET, {
          type: 6,
          amount: new BigNumber(5),
          requestId: 123,
          data: Buffer.from('hello')
        })
      }))

      const result = await sender.sendRequest(this.plugin, {
        destinationAccount: 'test.receiver',
        sharedSecret: SHARED_SECRET,
        sourceAmount: '10',
        requestId: 1234
      }) as sender.PskError
      assert(stub.calledOnce)
      assert.equal(result.fulfilled, false)
      assert.equal(result.code, 'F99')
      assert.equal(result.destinationAmount.toString(10), '0')
      assert.equal(result.data.toString('utf8'), '')
    })

    it('should resolve but not return the data or destination amount if the PSK request type does not match the ILP packet type it is attached to', async function () {
      const stub = sinon.stub(this.plugin, 'sendData').resolves(IlpPacket.serializeIlpReject({
        code: 'F99',
        message: '',
        triggeredBy: 'test.receiver',
        data: encoding.serializePskPacket(SHARED_SECRET, {
          type: 5,
          amount: new BigNumber(5),
          requestId: 1234,
          data: Buffer.from('hello')
        })
      }))

      const result = await sender.sendRequest(this.plugin, {
        destinationAccount: 'test.receiver',
        sharedSecret: SHARED_SECRET,
        sourceAmount: '10',
        requestId: 1234
      }) as sender.PskError
      assert(stub.calledOnce)
      assert.equal(result.fulfilled, false)
      assert.equal(result.code, 'F99')
      assert.equal(result.destinationAmount.toString(10), '0')
      assert.equal(result.data.toString('utf8'), '')
    })

  })
  
})

mock.stopAll()
mock.reRequire('crypto')
