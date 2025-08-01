const mongoose = require('mongoose');

const eventSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    image_url: {
        type: String,
        required: true 
    },
    date: {
        type: Date,
        required: true
    },
    location: {
        type: String,
        required: true
    },
    price: {
        type: Number,
        required: true
    },
    capacity: {
        type: Number,
        required: true
    },
    available_tickets: {
        type: Number
        // required: true
    },
});

eventSchema.pre('save', function(next) {
    if (this.isNew || this.isModified('capacity')) {
        this.available_tickets = this.capacity ;
    }
    next();
});


module.exports = mongoose.model('Event', eventSchema);