import 'mocha'
import * as sinon from 'sinon'
import { assert } from 'chai'
import * as PSK2 from '../src/index'

describe('Exports', function () {
  it('exports the sender and receiver functions directly', function () {
    assert.typeOf(PSK2.Receiver, 'function')
    assert.typeOf(PSK2.createReceiver, 'function')
  })

  it('exports the packet types and encoding functions', function () {
    assert.typeOf(PSK2.deserializePskPacket, 'function')
    assert.typeOf(PSK2.serializePskPacket, 'function')
    assert.typeOf(PSK2.TYPE_PSK2_CHUNK, 'number')
  })
})
