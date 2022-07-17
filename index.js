const express = require('express')
const app = express()
const jwt = require('jsonwebtoken')
const Web3 = require('web3')
const port = 4000

const web3 = new Web3('https://cloudflare-eth.com/')
const jwtSecret = 'some very secret value'

app.use(express.static('public'))

app.get('/nonce', (req, res) => {
  const nonce = new Date().getTime()
  const address = req.query.address

  const tempToken = jwt.sign({ nonce, address }, jwtSecret, { expiresIn: '60s' })
  const message = getSignMessage(address, nonce)

  res.json({ tempToken, message })
})

app.post('/verify', async (req, res) => {
  const authHeader = req.headers['authorization']
  const tempToken = authHeader && authHeader.split(" ")[1]

  if (tempToken === null) return res.sendStatus(403)

  const userData = await jwt.verify(tempToken, jwtSecret)
  const nonce = userData.nonce
  const address = userData.address
  const message = getSignMessage(address, nonce)
  const signature = req.query.signature

  const verifiedAddress = await web3.eth.accounts.recover(message, signature)

  if (verifiedAddress.toLowerCase() == address.toLowerCase()) {
    const token = jwt.sign({ verifiedAddress }, jwtSecret, { expiresIn: '1d' })
    res.json({ token })
  } else {
    res.sendStatus(403)
  }
})

app.get('/secret', authenticateToken, async (req, res) => {
  res.send(`Welcom address ${req.authData.verifiedAddress}`)
})

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]

  if (token == null) return res.sendStatus(401)

  jwt.verify(token, jwtSecret, (err, authData) => {
    console.log(err)

    if (err) return res.sendStatus(403)

    req.authData = authData

    next()
  })
}

const getSignMessage = (address, nonce) => {
  return `Please sign this message for address ${address}:\n\n${nonce}`
}

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})