require('dotenv').config();
const express = require('express');
const app = express();
const mongoose = require('mongoose');
const cors = require('cors');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const Jwt = require('jsonwebtoken');
const Razorpay = require('razorpay');
const crypto = require("crypto");


// MongoDB Models
const User = require('./models/User');
const Event = require('./models/Event');
const Booking = require('./models/Booking');

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
    .then(() => console.log('✅ Connected to MongoDB'))
    .catch(err => {
        console.error('❌ MongoDB connection failed:', err.message);
        process.exit(1);
    });

app.set("view engine", "ejs");
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 24 * 60 * 60 * 1000
    }
}));

const secret_jwt = process.env.SECRET_JWT;
const port = process.env.PORT ;
const ADMIN_SECRET_CODE = process.env.ADMIN_SECRET_CODE;

const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET,
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});

app.get('/', (req, res) => {
    const logoutSuccess = req.cookies.logoutSuccess;
    res.clearCookie('logoutSuccess');
    res.render('landing', { logoutSuccess });
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
});

app.get('/signup', (req, res) => {
    if (req.session.user) {
        if (req.session.user.role === 'admin') {
            return res.redirect('/admin');
        } else {
            return res.redirect('/user');
        }
    }
    res.render('signup.ejs');
});

app.post('/signup', async (req, res) => {
    const { username, email, password, role, secretCode } = req.body;

    if (role === 'admin' && secretCode !== ADMIN_SECRET_CODE) {
        return res.render('signup', { error: 'Invalid admin secret code' });
    }
    console.log('Signup Receieved', req.body);
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        const newUser = new User({
            username,
            email,
            password: hashedPassword,
            role
        });
        await newUser.save();
        res.redirect('/login');
    } catch (err) {
        console.error(err);
        res.status(500).send('Signup failed');
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });

        if (!user) {
            return res.render('login', { error: 'Invalid username or password' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.render('login.ejs', { error: 'Invalid username or password' });
        }

        req.session.user = {
            id: user._id,
            username: user.username,
            role: user.role
        };
        const token = Jwt.sign({ id: user._id, username: user.username, role: user.role }, secret_jwt, { expiresIn: '1h' });

        res.cookie('token', token, { httpOnly: true });
        req.session.loginSuccess = true;
        if (user.role === 'admin') {
            res.redirect('/admin');
        } else {
            res.redirect('/user');
        }
    } catch (error) {
        console.error(error);
        res.status(500).send('Something went wrong');
    }
});


function authMiddleware(req, res, next) {
    const token = req.cookies.token;
    if (!token) {
        return res.redirect('/login');
    }

    try {
        const decoded = Jwt.verify(token, secret_jwt);
        req.user = decoded;
        req.session.user = decoded;
        next();
    } catch (err) {
        res.status(400).send('Invalid token');
        res.clearCookie('token');
        res.redirect('/login');
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

app.get('/logout', (req, res) => {
    res.cookie('logoutSuccess', true, { httpOnly: true });
    req.session.destroy(err => {
        if (err) {
            console.error('Logout Error:', err);
            return res.status(500).send('Could not log out');
        }
    });
    res.clearCookie('token');
    res.redirect('/');
});

app.get("/user", authMiddleware, isUser, async (req, res) => {
    const loginSuccess = req.session.loginSuccess;
    delete req.session.loginSuccess;
    try {
        const events = await Event.find().sort({ date: 1 });
        res.render('user', { loginSuccess, events, user: req.session.user });
    } catch (err) {
        console.error(err);
        res.status(500).send('Database Error');
    }
});

app.get('/user/events', authMiddleware, isUser, async (req, res) => {
    try {
        const events = await Event.find({ date: { $gte: new Date() } }).sort({ date: 1 });
        res.render('userevents', { events });
    } catch (err) {
        console.error(err);
        res.status(500).send('Database Error');
    }
});

app.get('/book/:id', authMiddleware, (req, res) => {
    const id = req.params.id;
    const username = req.user.username;
    res.render('bookTicket', { username, id });
});

app.post('/book/:id', authMiddleware, async (req, res) => {
    const id = req.params.id;
    const { tickets } = req.body;

    try {
        const event = await Event.findById(id);
        if (!event) {
            return res.status(404).send('Event not found');
        }
        if (parseInt(tickets) > event.available_tickets) {
            return res.status(400).send('Not enough tickets available');
        }
        res.redirect(`/pay/${id}?price=${event.price}&tickets=${tickets}`);
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});

app.get('/success', authMiddleware, (req, res) => {
    res.redirect('/update');
});

app.get('/mybookings', authMiddleware, isUser, async (req, res) => {
    try {
        const bookings = await Booking.find({ user_id: req.user.id })
            .populate('event_id')
            .sort({ booking_date: -1 });

        const formattedBookings = bookings.map(booking => ({
            eventName: booking.event_id.name,
            location: booking.event_id.location,
            date: booking.event_id.date,
            price: booking.event_id.price,
            id: booking._id,
            tickets_booked: booking.tickets_booked,
            booking_date: booking.booking_date
        }));
        res.render('mybookings', { bookings: formattedBookings });
    } catch (err) {
        console.error(err);
        res.status(500).send('Error fetching bookings');
    }
});

app.get('/admin', authMiddleware, isAdmin, async (req, res) => {
    try {
        const events = await Event.find().sort({ date: 1 });
        res.render('admin', { events, user: req.session.user });
    } catch (err) {
        console.error(err);
        res.status(500).send('Database Error');
    }
});

app.get('/admin/dashboard', authMiddleware, isAdmin, async (req, res) => {
    try {
        const totalEvents = await Event.countDocuments();
        const totalUsers = await User.countDocuments({ role: 'user' });
        const upcomingEvents = await Event.countDocuments({ date: { $gte: new Date() } });
        const totalBookings = await Booking.countDocuments();
        const recentEvents = await Event.find().sort({ date: -1 }).limit(5);

        const chartData = await Booking.aggregate([
            {
                $group: {
                    _id: "$event_id",
                    bookingCount: { $sum: 1 }
                }
            },
            {
                $lookup: {
                    from: "events",
                    localField: "_id",
                    foreignField: "_id",
                    as: "eventDetails"
                }
            },
            {
                $unwind: "$eventDetails"
            },
            {
                $project: {
                    eventName: "$eventDetails.name",
                    bookingCount: "$bookingCount"
                }
            },
            {
                $sort: { bookingCount: -1 }
            }
        ]);

        const data = { totalEvents, totalUsers, upcomingEvents, totalBookings };
        res.render('dashboard', { data, recentEvents, chartData });
    } catch (err) {
        console.error(err);
        res.status(500).send('Database Error');
    }
});

app.get('/admin/events', authMiddleware, isAdmin, async (req, res) => {
    try {
        const events = await Event.find({ date: { $gte: new Date() } }).sort({ date: 1 });
        res.render('adminevents', { events });
    } catch (err) {
        console.error(err);
        res.status(500).send('Database Error');
    }
});

app.get('/addEvent', authMiddleware, isAdmin, (req, res) => {
    res.render('addEvent');
});

app.post('/add', authMiddleware, isAdmin, async (req, res) => {
    try {
        const newEvent = new Event(req.body);
        await newEvent.save();
        res.redirect('/admin');
    } catch (err) {
        console.error(err);
        res.status(500).send('Database Error');
    }
});

app.get('/delete', authMiddleware, isAdmin, async (req, res) => {
    try {
        const events = await Event.find().sort({ date: 1 });
        res.render('delete', { events });
    } catch (err) {
        console.error(err);
        res.status(500).send('Database Error');
    }
});

app.post('/delete', authMiddleware, isAdmin, async (req, res) => {
    const eventId = req.body.eventId;
    try {
        await Booking.deleteMany({ event_id: eventId });
        await Event.findByIdAndDelete(eventId);
        res.redirect('/admin');
    } catch (err) {
        console.error(err);
        res.status(500).send('Failed to delete event');
    }
});

app.get('/pay/:eventId', authMiddleware, async (req, res) => {
    const { price, tickets } = req.query;
    const eventId = req.params.eventId;
    const user = req.session.user;

    const amount = price * parseInt(tickets) * 100;
    const currency = "INR";

    const options = {
        amount: amount,
        currency: currency,
        receipt: `receipt_${Date.now()}`
    };

    razorpay.orders.create(options, (err, order) => {
        if (err) {
            console.error(err);
            return res.status(500).send("Order creation failed");
        }

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

app.post("/verify", express.json(), (req, res) => {
    const {
        razorpay_order_id,
        razorpay_payment_id,
        razorpay_signature
    } = req.body;

    const secret = process.env.RAZORPAY_KEY_SECRET;

    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature || !secret) {
        console.error("Missing required data for verification.");
        return res.status(400).send("Missing payment details.");
    }

    const generated_signature = crypto
        .createHmac("sha256", secret)
        .update(razorpay_order_id + "|" + razorpay_payment_id)
        .digest("hex");

    if (generated_signature === razorpay_signature) {
        console.log("Payment verified successfully.");
        return res.status(200).json({ success: true });
    } else {
        console.error("Signature mismatch. Verification failed.");
        return res.status(400).json({ success: false, message: "Invalid signature" });
    }
});

app.get('/update', authMiddleware, async (req, res) => {
    const booking = req.session.pendingBooking;
    if (!booking) {
        return res.redirect('/user');
    }

    const { userId, eventId, tickets } = booking;
    try {
        const event = await Event.findById(eventId);
        if (!event) {
            return res.status(404).send("Event not found");
        }

        const remaining = event.available_tickets - parseInt(tickets);
        if (remaining < 0) {
            return res.status(400).send("Not enough tickets available");
        }

        await Event.findByIdAndUpdate(eventId, { available_tickets: remaining });

        const newBooking = new Booking({
            user_id: userId,
            event_id: eventId,
            tickets_booked: tickets,
            booking_date: new Date()
        });
        await newBooking.save();

        delete req.session.pendingBooking;

        const updatedEvent = await Event.findById(eventId);
        res.render('confirmation', { event: updatedEvent, userId, tickets });
    } catch (err) {
        console.error(err);
        res.status(500).send("Failed to complete booking");
    }
});

app.get('/contact', (req, res) => {
    res.render('contact');
});

app.post('/contact', (req, res) => {
    const { name, email, subject, message } = req.body;
    res.send('Thank you for contacting us!');
});

app.get('/privacy', (req, res) => {
    res.render('privacy');
});

app.get('/terms', (req, res) => {
    res.render('terms');
});

app.get('/faqs', (req, res) => {
    res.render('faqs');
});
