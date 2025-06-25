const express = require('express') ;
const app = express() ;
const mysql = require('mysql2') ;
const cors = require('cors') ;
const session = require('express-session') ;
const bodyParser = require('body-parser');
const path = require('path');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs') ;
const Jwt = require('jsonwebtoken');
const Razorpay = require('razorpay');
require('dotenv').config();

 
app.set("view engine", "ejs");
app.use(express.json()) ;
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public')) ;
app.use(bodyParser.urlencoded({extended : true})) ;
app.use(cookieParser());
app.use(session({
  secret: process.env.SESSION_SECRET,      
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000  
  }     
}));
// console.log("Session Secret:", process.env.SESSION_SECRET);
const secret_jwt = process.env.SECRET_JWT;
const port = process.env.PORT || 5000;
const ADMIN_SECRET_CODE = process.env.ADMIN_SECRET_CODE;

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
}) ;
const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET,
});


app.listen(port, ()=>{
    console.log(`Server is running on port ${port}`);
})

app.get('/', (req, res) => {
  res.render('landing'); 
});

app.get('/login', (req, res) => {
    if (req.session && req.session.user) {
        if (req.session.user.role === 'admin') {
            return res.redirect('/admin');
        } else {
            return res.redirect('/user');
        }
    }
    res.render('login.ejs');
})
app.get('/signup', (req, res) => {
    if (req.session.user) {
        if (req.session.user.role === 'admin') {
            return res.redirect('/admin');
        } else {
            return res.redirect('/user');
        }
    }
    res.render('signup.ejs');
})

app.post('/signup', async (req, res) => {
    const {username, email, password, role, secretCode} = req.body ;

    if (role === 'admin' && secretCode !== ADMIN_SECRET_CODE) {
    return res.render('signup', { error: 'Invalid admin secret code' });
  }
    console.log('Signup Receieved', req.body) ;
    const hashedPassword = await bcrypt.hash(password, 10);

    db.query('Insert into event_users(username, email, password, role) values (?, ?, ?, ?)', [username, email, hashedPassword, role], (err, results) => {
        if(err) return res.status(500).send('Signup failed') ;
        // res.send('User registered successfully') ;
        res.redirect('/login') ;
    });
});

app.post('/login', async (req, res) => {
    const {username, password} = req.body;
    db.query('SELECT * FROM event_users WHERE username = ?', [username], async (err, results) => {
        if (err || results.length === 0) {
            return res.render('login', { error: 'Invalid username or password' });
        }

        const user = results[0];
        if (!user.password) {
            return res.status(401).send('Invalid credentials');
        }
        try 
        {
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
            return res.render('login.ejs', { error: 'Invalid username or password'});
           }

            req.session.user = {
                id: user.id,
                username: user.username,
                role: user.role
            };
            const token = Jwt.sign({ id: user.id, username: user.username, role: user.role }, secret_jwt, { expiresIn: '1h' });

            res.cookie('token', token, { httpOnly: true });

            if (user.role === 'admin') 
            {
                res.redirect('/admin');
            } 
            else 
            {
                res.redirect('/user');
            }

        } catch (error) {
            console.error(error);
            res.status(500).send('Something went wrong');
        }
    });
});


function authMiddleware(req, res, next) {
    const token = req.cookies.token;
//   console.log(req.cookies.token) ;
    if (!token) 
    {
        return res.redirect('/login') ;    
    }

    try 
    {
        const decoded = Jwt.verify(token, secret_jwt);
        // console.log("Decoded token:", decoded);
        req.user = decoded;
        req.session.user = decoded; 
        next();
    } 
    catch (err) 
    {
        res.status(400).send('Invalid token');
        res.clearCookie('token') ;
        res.redirect('/login') ;
    }
}

function isAdmin(req, res, next) {
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    return res.status(403).send('Access denied. Admins only.');
  }
}

function isUser(req, res, next) {
  if (req.user && req.user.role === 'user') {
    next();
  } else {
    return res.status(403).send('Access denied. Users only.');
  }
}

module.exports = { isAdmin, isUser };

app.get('/logout', (req, res) => {

    req.session.destroy(err => {
        if (err) {
            console.error('Logout Error:', err);
            return res.status(500).send('Could not log out');
        }
    })
    res.clearCookie('token');
    res.redirect('/');
});

app.get("/user", authMiddleware, isUser, (req, res) => {
    db.query('SELECT * from events ORDER BY date ASC', (err, results) => {
        if(err) 
        {
            console.log(err);
            return res.status(500).send('Database Error') ;
        }
        res.render('user',{events:results , user: req.session.user});
    }) ;
})

app.get('/user/events', authMiddleware, isUser, (req, res) => {
    const sql = `SELECT * from events WHERE date >= CURDATE() ORDER BY date ASC` ;

    db.query(sql, (err, results) => {
        if(err) return res.status(500).send('Database Error') ;
        res.render('userevents', {events:results});
    })
})

app.get('/book/:id', authMiddleware, (req, res) => {
    const id = req.params.id ;
    const username = req.user.username ;
    console.log(username, id) ;
    res.render('bookTicket', {username, id}) ;
})

app.post('/book/:id', authMiddleware, (req, res) => {
    const id = req.params.id ;
    const {tickets} = req.body ;

    db.query(`SELECT available_tickets from events WHERE id = ?`, [id], (err, results) => {
        if(err) return res.status(500).send('Event not Found') ;
        const available = results[0].available_tickets ;
        if(parseInt(tickets) > available) return res.status(400).send('Not enough tickets available') ;

        db.query(`SELECT name, date, location, price FROM events WHERE id = ?`, [id], (err4, eventResult) => {
            if (err4 || eventResult.length === 0) return res.status(500).send('Event fetch failed');

            const price = eventResult[0].price;
            res.redirect(`/pay/${id}?price=${price}&tickets=${tickets}`);
        })
    })
})

app.get('/success', authMiddleware, (req, res) => {
    res.redirect('/update') ;
})

app.get('/mybookings', authMiddleware, isUser, (req, res) => {

    const sql = `SELECT e.name as eventName, e.location, e.date, e.price, b.id, b.tickets_booked, b.booking_date 
    FROM bookings b
    JOIN events e 
    ON e.id = b.event_id
    WHERE b.user_id = ? 
    AND e.date >= CURDATE()` ;

    db.query(sql, [req.user.id], (err, results) => {
        if (err) 
        {
            console.log(err) ;
            return res.status(500).send('Error fetching bookings')
        }
        res.render('mybookings', {bookings: results})
    }) ;
})

app.get('/admin',authMiddleware, isAdmin, (req,res)=>{
    db.query('SELECT * from events ORDER BY date ASC', (err, results) => {
        if(err) return res.status(500).send('Database Error') ;
        res.render('admin',{events:results, user: req.session.user});
    }) ;
}) ;

app.get('/admin/dashboard', authMiddleware, isAdmin, (req, res) => {
    db.query(`SELECT 
        (SELECT COUNT(*) from events) AS totalEvents,
        (SELECT COUNT(*) from event_users WHERE role = 'user') AS totalUsers,
        (SELECT COUNT(*) from events WHERE date >= CURDATE()) AS upcomingEvents,
        (SELECT COUNT(*) from bookings) AS totalBookings` , (err, results) => {
            if (err) return res.status(500).send('Database Error');
        
        const data = results[0];
        db.query('SELECT * FROM events ORDER BY date DESC LIMIT 5', (err2, recentEvents) => {
            if (err2) return res.status(500).send('Database Error');

            db.query(`
                SELECT e.name AS eventName , COUNT(b.id) AS bookingCount
                FROM events e
                JOIN bookings b 
                ON e.id = b.event_id
                GROUP BY e.id
                ORDER BY bookingCount DESC`, (err3, chartData) => {
                    if(err3) return res.status(500).send('Chart data Error');
                    // console.log(chartData) ;
                    res.render('dashboard', { data, recentEvents, chartData });
                }) ;
        }) ;
    });
}) ;

app.get('/admin/events', authMiddleware, isAdmin, (req, res) => {
    const sql = `SELECT * from events WHERE date >= CURDATE() ORDER BY date ASC` ;

    db.query(sql, (err, results) => {
        if(err) return res.status(500).send('Database Error') ;
        res.render('adminevents', {events:results});
    })
})

app.get('/addEvent', authMiddleware, isAdmin, (req, res) => {
    res.render('addEvent');
})

app.post('/add', authMiddleware, isAdmin, (req, res) => {
    db.query('Insert into events SET ?', req.body, (err, results) => {
        if (err) return res.status(500).send('Database Error');
        res.redirect('/admin');
    }) 
}) 

app.get('/delete', authMiddleware, isAdmin, (req, res) => {
    const sql = `SELECT id, name, date, location, price FROM events ORDER BY date ASC` ;
    db.query(sql, (err, results) =>{
        if(err) return res.status(500).send('Database Error') ;
        res.render('delete', {events:results}) ;
    }) ;
})
app.post('/delete', authMiddleware, isAdmin, (req, res) => {
    const eventId = req.body.eventId;
    
    // if event_id exits in bookings table also then first delete from bookings table 
    // then from events table to maintain refrential integrity //
    db.query('DELETE FROM bookings WHERE event_id = ?', [eventId], (err1, result1) => {
        if (err1) {
            console.error(err1);
            return res.status(500).send('Failed to delete bookings');
        }

        db.query('DELETE FROM events WHERE id = ?', [eventId], (err2, result2) => {
            if (err2) {
                console.error(err2);
                return res.status(500).send('Failed to delete event');
            }

            res.redirect('/admin');
        });
    });
})

app.get('/pay/:eventId', authMiddleware, (req, res) => {
    const { price, tickets } = req.query;
    const eventId = req.params.eventId ;
    const user = req.session.user;

    const amount = price * parseInt(tickets) * 100 ;
    const currency = "INR";

    const options = {
        amount: amount,
        currency: currency,
        receipt: `receipt_${Date.now()}`
    };

    razorpay.orders.create(options, (err, order) => {
        if (err) return res.status(500).send("Order creation failed");

        req.session.pendingBooking = {
            userId: user.id,
            eventId,
            tickets,
            amount
        };
        res.render('payment', {
            user,
            orderId: order.id,
            amount,
            keyId: process.env.RAZORPAY_KEY_ID
        });
    });
});


const crypto = require("crypto");

app.post("/verify", express.json(), (req, res) => {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

    const hmac = crypto.createHmac("sha256", process.env.RAZORPAY_SECRET);
    hmac.update(razorpay_order_id + "|" + razorpay_payment_id);
    const generated_signature = hmac.digest("hex");

    if (generated_signature === razorpay_signature) {
        res.redirect("/success");
    } else {
        res.status(400).send("Payment verification failed");
    }
});


app.get('/update', authMiddleware, (req, res) => {
    const booking = req.session.pendingBooking;

    const {userId, eventId, tickets} = booking ;
    const sql = `SELECT available_tickets from events where id = ?` ;
    db.query(sql, [eventId], (err,result) => {
        if(err) return res.status(500).send("Event fetch failed");
        const available = result[0].available_tickets ;
        const remaining = available - parseInt(tickets) ;

        db.query(`Update events set available_tickets = ? WHERE id = ?`, [remaining, eventId], (err1, results) => {
           if(err1) return res.status(500).send("Failed to update tickets");

           db.query('INSERT INTO bookings (user_id, event_id, tickets_booked, booking_date) VALUES (?, ?, ?, NOW())',
                [userId, eventId, tickets], (err3) => {
                    if (err3) return res.status(500).send("Booking insert failed");

                    delete req.session.pendingBooking;
                    
                    db.query(`SELECT * FROM events WHERE id = ?`, [eventId], (err4, result) => {
                        if (err4) return res.status(500).send("Event fetch failed");
                        res.render('confirmation', {event: result[0], userId, tickets});
                })
            });
        })
    }) 
})



app.get('/contact', (req, res) => {
  res.render('contact');
});

app.post('/contact', (req, res) => {
  const { name, email, subject, message } = req.body;
  res.send('Thank you for contacting us!');
});

app.get('/privacy', (req, res) => {
    res.render('privacy') ;
})

app.get('/terms', (req, res) => {
    res.render('terms') ;
})

app.get('/faqs', (req, res) => {
    res.render('faqs') ;
})
