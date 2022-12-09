import './env.js'

import crypto from 'crypto'
import express from 'express'
import jwt from 'jsonwebtoken'
import fetch from 'node-fetch'
import { Sequelize, DataTypes } from 'sequelize'

// ----------------------------------------------------------------------- db --

const sequelize = new Sequelize(
  process.env.DB_NAME,
  process.env.DB_USER,
  process.env.DB_PASSWORD,
  {
    host: process.env.DB_HOST,
    dialect: process.env.DB_DIALECT,
  },
)

const User = sequelize.define('user', {
  username: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
    set: function (value) {
      this.setDataValue('username', value.toLowerCase())
    },
  },
  password: {
    type: DataTypes.STRING,
    get: function () {
      return () => this.getDataValue('password')
    },
  },
  salt: {
    type: DataTypes.STRING,
    get: function () {
      return () => this.getDataValue('salt')
    },
  },
  lnbits_id: {
    type: DataTypes.STRING,
  },
  lnbits_inkey: {
    type: DataTypes.STRING,
  },
  lnbits_adminkey: {
    type: DataTypes.STRING,
  },
})

User.saltedAndHashedPassword = (password, salt) =>
  crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex')

User.passwordMatches = (password, user) =>
  User.saltedAndHashedPassword(password, user.salt()) === user.password()

User.beforeCreate(user => {
  if (user.changed('password')) {
    user.salt = crypto.randomBytes(16).toString('hex')
    user.password = User.saltedAndHashedPassword(user.password(), user.salt())
  }
})

User.beforeUpdate(user => {
  if (user.changed('password')) {
    user.salt = crypto.randomBytes(16).toString('hex')
    user.password = User.saltedAndHashedPassword(user.password(), user.salt())
  }
})

try {
  await sequelize.authenticate()
  console.log('db connection: ok')
} catch (error) {
  console.error('db connection: error', error)
  process.exit(1)
}

await sequelize.sync()

// --------------------------------------------------------------- middleware --

const log = (req, res, next) => {
  console.log(
    `Received: ${req.method} ${req.path} Body: ${JSON.stringify(req.body)}`,
  )

  next()
}

const authenticated = async (req, res, next) => {
  const authHeader = req.headers.authorization

  if (!authHeader) {
    res.status(401).json({
      message: 'missing auth header',
    })

    return
  }

  const token = authHeader.split(' ')[1]

  jwt.verify(
    token,
    process.env.ACCESS_TOKEN_SECRET,
    { algorithms: ['HS256'] },
    async (err, payload) => {
      if (err) {
        res.status(403).send({
          message: 'invalid auth header',
        })

        return
      }

      const users = await User.findAll({
        where: { username: payload.username },
      })

      const user = users instanceof Array ? users[0] : null

      if (user === null) {
        res.status(403).json({
          message: 'invalid auth header',
        })

        return
      }

      req.user = {
        username: user.username,
        lnbits_inkey: user.lnbits_inkey,
        lnbits_adminkey: user.lnbits_adminkey,
      }

      next()
    },
  )
}

// ------------------------------------------------------------------- routes --

const router = express.Router()

router.post('/v2/users', async (req, res) => {
  if (!req.body.login || !req.body.password) {
    res.status(400).json({
      message: 'needs login and password',
    })

    return
  }

  try {
    const user = await User.create({
      username: req.body.login,
      password: req.body.password,
    })

    const response = await fetch(
      `https://${process.env.LNBITS_HOST}/usermanager/api/v1/users`,
      {
        method: 'post',
        body: JSON.stringify({
          admin_id: process.env.LNBITS_USR,
          user_name: user.username,
          wallet_name: `wallet_${user.username}`,
        }),
        headers: {
          'X-Api-Key': process.env.LNBITS_ADMIN_KEY,
          'Content-type': 'application/json',
        },
      },
    )

    const lnbitsData = await response.json()

    if (!response.ok) {
      await user.destroy()

      res
        .status(response.status)
        .json({ message: 'lnbits error', data: lnbitsData })

      return
    }

    const wallet = lnbitsData.wallets[0]

    user.lnbits_id = lnbitsData.id
    user.lnbits_inkey = wallet.inkey
    user.lnbits_adminkey = wallet.adminkey

    await user.save()

    res.status(201).json({ login: user.username, password: req.body.password })
  } catch (error) {
    console.log(error)
    res.status(500).json({
      message: 'error during signup: could not create user',
      error,
    })
  }
})

router.post('/auth', async (req, res) => {
  if (req.body.login && req.body.password) {
    // login with username and password
    try {
      const users = await User.findAll({
        where: { username: req.body.login },
      })

      const user = users instanceof Array ? users[0] : null

      if (user === null) {
        res.status(403).json({
          message: 'invalid credentials',
        })

        return
      }

      const passwordIsCorrect = User.passwordMatches(req.body.password, user)

      if (!passwordIsCorrect) {
        res.status(403).json({
          message: 'invalid credentials',
        })

        return
      }

      const accessToken = jwt.sign(
        { username: user.username },
        process.env.ACCESS_TOKEN_SECRET,
        { algorithm: 'HS256', expiresIn: '1d' },
      )

      const refreshToken = jwt.sign(
        { username: user.username },
        process.env.REFRESH_TOKEN_SECRET,
        { algorithm: 'HS256', expiresIn: '7d' },
      )

      res.status(200).json({
        access_token: accessToken,
        refresh_token: refreshToken,
      })
    } catch (err) {
      res.status(500).json({
        message: err.message || 'error during login',
        err,
      })
    }
  } else if (req.body.refresh_token) {
    // refresh access token
    jwt.verify(
      req.body.refresh_token,
      process.env.REFRESH_TOKEN_SECRET,
      { algorithms: ['HS256'] },
      async (err, payload) => {
        if (err) {
          res.status(403).send({
            message: 'invalid refresh token',
          })

          return
        }

        const accessToken = jwt.sign(
          { username: payload.username },
          process.env.ACCESS_TOKEN_SECRET,
          { algorithm: 'HS256', expiresIn: '1d' },
        )

        const refreshToken = jwt.sign(
          { username: payload.username },
          process.env.REFRESH_TOKEN_SECRET,
          { algorithm: 'HS256', expiresIn: '7d' },
        )

        res.status(200).json({
          access_token: accessToken,
          refresh_token: refreshToken,
        })
      },
    )
  } else {
    res.status(400).json({
      message: 'needs login and password or refresh_token',
    })
  }
})

router.get('/v2/balance', authenticated, async (req, res) => {
  const response = await fetch(
    `https://${process.env.LNBITS_HOST}/api/v1/wallet`,
    {
      headers: {
        'X-Api-Key': req.user.lnbits_inkey,
      },
    },
  )

  const lnbitsData = await response.json()

  if (!response.ok) {
    res
      .status(response.status)
      .json({ message: 'lnbits error', data: lnbitsData })

    return
  }

  res.status(200).json({
    balance: lnbitsData.balance,
    currency: 'BTC',
    unit: 'msat',
  })
})

router.post('/v2/invoices', authenticated, async (req, res) => {
  if (!req.body.amount || !req.body.description) {
    res.status(400).json({
      message: 'needs amount and description',
    })
  }

  const response = await fetch(
    `https://${process.env.LNBITS_HOST}/api/v1/payments`,
    {
      method: 'post',
      body: JSON.stringify({
        out: false,
        amount: req.body.amount,
        memo: req.body.description,
      }),
      headers: {
        'X-Api-Key': req.user.lnbits_inkey,
        'Content-type': 'application/json',
      },
    },
  )

  const lnbitsData = await response.json()

  if (!response.ok) {
    res
      .status(response.status)
      .json({ message: 'lnbits error', data: lnbitsData })

    return
  }

  res.status(201).json({
    expires_at: 'todo',
    payment_hash: lnbitsData.payment_hash,
    payment_request: lnbitsData.payment_request,
  })
})

router.post('/v2/payments/bolt11', authenticated, async (req, res) => {
  if (!req.body.invoice || !req.body.amount) {
    res.status(400).json({
      message: 'needs invoice and amount',
    })
  }

  const response = await fetch(
    `https://${process.env.LNBITS_HOST}/api/v1/payments`,
    {
      method: 'post',
      body: JSON.stringify({
        out: true,
        bolt11: req.body.invoice,
      }),
      headers: {
        'X-Api-Key': req.user.lnbits_adminkey,
        'Content-type': 'application/json',
      },
    },
  )

  const lnbitsData = await response.json()

  if (!response.ok) {
    res
      .status(response.status)
      .json({ message: 'lnbits error', data: lnbitsData })

    return
  }

  res.status(200).json({
    amount: 'todo',
    description: 'todo',
    description_hash: 'todo',
    destination: 'todo',
    fee: 'todo',
    payment_hash: lnbitsData.payment_hash,
    payment_preimage: 'todo',
    payment_request: req.body.invoicd,
  })
})

// ---------------------------------------------------------------------- app --

const app = express()

app.use(express.json())
app.use(router)

if (process.env.LOG_REQUESTS) {
  app.use(log)
}

const server = app.listen(process.env.PORT, () =>
  console.log(`listening on port: ${process.env.PORT}`),
)

process.on('SIGTERM', () => {
  server.close(async () => await sequelize.close())
})
