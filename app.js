import express from 'express'
import mysql from 'mysql'
import session from 'express-session'
import bcrypt from 'bcrypt'


const app = express()

const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'agrihub',
})

connection.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL database:', err)
        return
    }
    console.log('Connected to MySQL database!')
})

app.set('view engine', 'ejs')

app.use(express.static('public'))

app.use(express.urlencoded({ extended: false }))


// Prepare to use session
app.use(session({
    secret: 'agrhub',
    saveUninitialized: false,
    resave: true
}))

// Continue to check if the user is logged in
app.use((req, res, next) => {
    res.locals.isLogedIn = (req.session.userID !== undefined)
    next()
})

function loginRequired(req, res) {
    res.locals.isLogedIn || res.redirect('/login')
}

app.get('/', (req, res) => {
    res.render('index.ejs')
})

app.get('/signupsignin', (req, res) => {
    res.render('signinsignup.ejs')
})

app.get('/register', (req, res) => {
    if (req.session.user) {
        res.redirect('/')
    } else {
        res.render('forms.ejs')
    }
})

app.post('/register', (req, res) => {
    connection.query(
        'SELECT email FROM users WHERE email = ?',
        [req.body.email],
        (selectErr, data) => {
            if (selectErr) {
                console.log('SQL error: ' + selectErr)
                res.render('forms.ejs', {
                    error: 'An error occurred. Please try again later.',
                })
            } else {
                if (data.length > 0) {
                    res.render('forms.ejs', { emailError: 'Email already exists' })
                } else {
                    if (req.body.confirmPassword === req.body.password) {
                        const salt = bcrypt.genSaltSync(saltRounds)
                        const hashedPassword = bcrypt.hashSync(req.body.password, salt)
                        connection.query(
                            'INSERT INTO users(username, email, password) VALUES(?, ?, ?)',
                            [req.body.username, req.body.email, hashedPassword],
                            (err) => {
                                if (err) {
                                    console.log('SQL error: ' + err)
                                    res.render('forms.ejs', {
                                        error: 'An error occurred. Please try again later.',
                                    })
                                } else {
                                    res.redirect('/login')
                                }
                            }
                        )
                    } else {
                        res.render('forms.ejs', {
                            passwordError: 'Password and confirm password do not match',
                        })
                    }
                }
            }
        }
    )
})

app.get('/login', (req, res) => {
    res.render('forms.ejs')
})

app.post('/login', (req, res) => {
    console.log('Login route triggered')
    // Fetch user data from the database based on the provided email
    connection.query(
        'SELECT * FROM users WHERE email = ?',
        [req.body.email],
        (selectErr, data) => {
            if (selectErr) {
                console.log('SQL error: ' + selectErr)
                res.render('forms.ejs', {
                    error: 'An error occurred. Please try again later.',
                })
            } else {
                if (data.length > 0) {
                    // Perform password comparison asynchronously
                    bcrypt.compare(
                        req.body.password,
                        data[0].password,
                        (compareErr, isPasswordCorrect) => {
                            if (compareErr) {
                                console.log('Password comparison error:', compareErr)
                                res.render('forms.ejs', {
                                    error: 'An error occurred. Please try again later.',
                                })
                            } else if (isPasswordCorrect) {
                                // Set session variables to indicate successful login
                                req.session.userID = data[0].u_id
                                console.log('Redirecting to /courses')
                                res.redirect('/courses')
                                console.log('Redirection executed')
                            } else {
                                // Password incorrect
                                res.render('forms.ejs', {
                                    loginError: 'Password incorrect',
                                })
                            }
                        }
                    )
                } else {
                    // User not found
                    res.render('forms.ejs', {
                        loginError: 'Account does not exist. Please create one',
                    })
                }
            }
        }
    )
})

app.get('/logout', (req, res) => {
    loginRequired(req, res)
    // Destroy the session and redirect to the home page
    req.session.destroy((err) => {
        if (err) {
            console.log('Error destroying session:', err)
        }
        res.redirect('/')
    })
})


const PORT = process.env.PORT || 4
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`)
})