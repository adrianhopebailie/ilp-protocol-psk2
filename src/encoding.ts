import * as assert from 'assert'
import * as crypto from 'crypto'
import * as oer from 'oer-utils'
import BigNumber from 'bignumber.js'
import * as Long from 'long'
import * as constants from './constants'
import { SocketInfo, SocketCtrlMessage, SocketCtrlBits } from './socket';
import { write } from 'fs';
import { Buffer } from 'buffer';

export enum Type {
  Request = 4,
  Response = 5,
  Error = 6
}

export interface PskPacket {
  type: Type,
  requestId: number,
  amount: BigNumber,
  data: Buffer,
  socketInfo?: SocketInfo
  socketCtrl?: SocketCtrlMessage
}

export function serializePskPacket (sharedSecret: Buffer, pskPacket: PskPacket, socketCtrl?: SocketCtrlMessage , socketInfo?: SocketInfo): Buffer {
    const {
    type,
    requestId,
    amount,
    data
  } = pskPacket
  assert(Number.isInteger(requestId) && requestId <= constants.MAX_UINT32, 'requestId must be a UInt32')
  assert(amount instanceof BigNumber && amount.isInteger() && amount.lte(constants.MAX_UINT64), 'amount must be a UInt64')

  const writer = new oer.Writer()
  writer.writeUInt8(type)
  writer.writeUInt32(requestId)
  writer.writeUInt64(bigNumberToHighLow(amount))
  writer.writeVarOctetString(data)

  if(socketInfo && socketCtrl) {
    let ctrlBits = 0
    ctrlBits |= socketInfo.isAutoIncrementingTarget ? SocketCtrlBits.IsAutoIncrementing : 0
    ctrlBits |= socketCtrl.enableAutoIncrementingTarget ? SocketCtrlBits.EnableAutoIncrementing : 0
    ctrlBits |= socketCtrl.targetDelta.isNegative() ? SocketCtrlBits.TargetDeltaIsNegative : 0

    writer.writeInt(ctrlBits, 1)
    writer.writeVarOctetString(Buffer.from(socketInfo.address, 'utf8'))
    writer.writeUInt64(bigNumberToHighLow(socketInfo.balance))
    writer.writeUInt64(bigNumberToHighLow(socketInfo.targetBalance))
    writer.writeUInt64(bigNumberToHighLow(socketInfo.sendingRate.shiftedBy(15).decimalPlaces(0, BigNumber.ROUND_DOWN)))
    writer.writeUInt64(bigNumberToHighLow(socketInfo.mtu))
    writer.writeUInt64(bigNumberToHighLow(socketCtrl.targetDelta.absoluteValue()))
  }

  const plaintext = writer.getBuffer()

  const ciphertext = encrypt(sharedSecret, plaintext)
  return ciphertext
}

export function deserializePskPacket (sharedSecret: Buffer, buffer: Buffer): PskPacket {
  const plaintext = decrypt(sharedSecret, buffer)
  const reader = oer.Reader.from(plaintext)

  const type = reader.readUInt8()
  assert(Type[type], 'PSK packet has unexpected type: ' + type)
  const requestId = reader.readUInt32()
  const amount = highLowToBigNumber(reader.readUInt64())
  const data = reader.readVarOctetString()

  //TODO Is there a better method for this in reader?
  if(reader.buffer.length > reader.cursor) {
    const ctrlBits = reader.readInt(1)
    const isAutoIncrementingTarget = (ctrlBits & SocketCtrlBits.IsAutoIncrementing) > 0
    const enableAutoIncrementingTarget = (ctrlBits & SocketCtrlBits.EnableAutoIncrementing) > 0
    const address = reader.readVarOctetString().toString('utf8')
    const balance = highLowToBigNumber(reader.readUInt64())
    const targetBalance = highLowToBigNumber(reader.readUInt64())
    const sendingRate = highLowToBigNumber(reader.readUInt64()).shiftedBy(-15)
    const mtu = highLowToBigNumber(reader.readUInt64())
    const targetDelta = highLowToBigNumber(reader.readUInt64())

    return {
      type,
      requestId,
      amount,
      data,
      socketCtrl : {
       enableAutoIncrementingTarget,
       targetDelta: ((ctrlBits & SocketCtrlBits.TargetDeltaIsNegative) > 0) ? targetDelta.negated() : targetDelta
      },
      socketInfo : {
        address,
        balance,
        targetBalance,
        sendingRate,
        mtu,
        isAutoIncrementingTarget
      }
    }
  }

  return {
    type,
    requestId,
    amount,
    data
  }

}

function encrypt (secret: Buffer, data: Buffer): Buffer {
  const iv = crypto.randomBytes(constants.IV_LENGTH)
  const pskEncryptionKey = hmac(secret, Buffer.from(constants.PSK_ENCRYPTION_STRING, 'utf8'))
  const cipher = crypto.createCipheriv(constants.ENCRYPTION_ALGORITHM, pskEncryptionKey, iv)

  const encryptedInitial = cipher.update(data)
  const encryptedFinal = cipher.final()
  const tag = cipher.getAuthTag()
  return Buffer.concat([
    iv,
    tag,
    encryptedInitial,
    encryptedFinal
  ])
}

function decrypt (secret: Buffer, data: Buffer): Buffer {
  assert(data.length > 0, 'cannot decrypt empty buffer')
  const pskEncryptionKey = hmac(secret, Buffer.from(constants.PSK_ENCRYPTION_STRING, 'utf8'))
  const nonce = data.slice(0, constants.IV_LENGTH)
  const tag = data.slice(constants.IV_LENGTH, constants.IV_LENGTH + constants.AUTH_TAG_LENGTH)
  const encrypted = data.slice(constants.IV_LENGTH + constants.AUTH_TAG_LENGTH)
  const decipher = crypto.createDecipheriv(constants.ENCRYPTION_ALGORITHM, pskEncryptionKey, nonce)
  decipher.setAuthTag(tag)

  return Buffer.concat([
    decipher.update(encrypted),
    decipher.final()
  ])
}

function hmac (key: Buffer, message: Buffer): Buffer {
  const h = crypto.createHmac('sha256', key)
  h.update(message)
  return h.digest()
}

// oer-utils returns [high, low], whereas Long expects low first
function highLowToBigNumber (highLow: number[]): BigNumber {
  // TODO use a more efficient method to convert this
  const long = Long.fromBits(highLow[1], highLow[0], true)
  return new BigNumber(long.toString(10))
}

function bigNumberToHighLow (bignum: BigNumber): number[] {
  const long = Long.fromString(bignum.toString(10), true)
  return [long.getHighBitsUnsigned(), long.getLowBitsUnsigned()]
}
