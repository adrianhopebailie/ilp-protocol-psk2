const { PaymentSocketServer, PaymentSocket} = require('.')
const IlpPluginBtp = require('ilp-plugin-btp')
const crypto = require('crypto')
const BigNumber = require('bignumber.js')

async function run () {
  
  const server = new PaymentSocketServer(new IlpPluginBtp({ server: 'btp+ws://:server@localhost:7768' }))
  await server.bind()

  const connectionId = crypto.randomBytes(32)
  const {destinationAccount, sharedSecret} = await server.listen(connectionId)
  server.accept((ctrlMessage) => {
    //Don't accept requests to decrease target (send)
    if(ctrlMessage.targetDelta < 0) {
      ctrlMessage.targetDelta = 0
    }
    return ctrlMessage;
  }, connectionId).then((serverSocket) => {
    serverSocket.onPaymentReceived.subscribe((eventSource, amount) => {
      console.log(`Received ${amount} from server.`)
    })
    serverSocket.connect({
      initialBalance: new BigNumber(0),
      initialTargetBalance: new BigNumber(0),
      estimatedCurrentRate: new BigNumber(1),
      isAutoIncrementingTarget: false,
      requestedRemoteTarget: new BigNumber(0),
      requestAutoIncrementingTargetAtRemote: false
    })
  })


  const clientSocket = new PaymentSocket({
    plugin: new IlpPluginBtp({ server: 'btp+ws://:client@localhost:7768' }),
    ctrlMessageHandler: (msg) => { return msg } //Accept everything
  })
  await clientSocket.bind(sharedSecret)

  await clientSocket.connect({
    initialBalance: new BigNumber(200),
    initialTargetBalance: new BigNumber(0),
    estimatedCurrentRate: new BigNumber(1),
    isAutoIncrementingTarget: true,
    requestedRemoteTarget: new BigNumber(0),
    requestAutoIncrementingTargetAtRemote: true
  }, destinationAccount)
  
  clientSocket.onPaymentSent((eventSource, amount) => {
    console.log(`Sent ${amount} from client.`)
  })
}

run().catch(err => console.log(err))

//Server listeneing at : test.moneyd..local.s-rNM0M7MbUlI1EDLJs-ei56p3ONXezfDdbGJoCFPAY.ME1J17i2wvcHc4c31BPWKu98bWF0QCGpi7Fa-eWoeLS6P0dVBBxFDt2VCtdBeI_6IoU
//Client listeneing at : test.moneyd..local.lI_mA_YdwDa1xZbcCf484_PTDckPAkyF88gtssyrZ50.wVm4HvQWE0CnyGDstIs91Ozt
//