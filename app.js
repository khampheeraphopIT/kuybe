var express = require('express')
var cors = require('cors')
var app = express()
var bodyParser = require('body-parser')
var jsonParser = bodyParser.json()
const bcrypt = require('bcrypt');
const saltRounds = 10;
var jwt = require('jsonwebtoken');
const secret = 'backend-Test-2024'
app.use(express.json())
app.use(bodyParser.json());

app.use(cors())

const mysql = require('mysql2');

const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    database: 'mydb'
})

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.status(401).json({ status: 'forbidden', message: 'No token provided.' });

    jwt.verify(token, secret, (err, user) => {
        if (err) return res.status(403).json({ status: 'forbidden', message: 'Please login' });
        console.log('Decoded token', user);

        // เพิ่ม role ลงใน req.user เพื่อให้สามารถเข้าถึงได้ภายหลัง
        req.user = { userId: user.userId, email: user.email, role: user.role };
        next();
    });
}


app.post('/register', jsonParser, function (req, res, next) {
    const { email, password, fname, lname, phoneNumber} = req.body;

    bcrypt.hash(password, saltRounds, function (err, hash) {
        if (err) {
            return res.status(500).json({ status: 'error', message: 'Failed to hash password' });
        }

        connection.execute(
            'INSERT INTO users (email, password , fname , lname, phoneNumber ) VALUES (?,?,?,?,?)',
            [email, hash, fname, lname, phoneNumber],
            function (err, results, fields) {
                if (err) {
                    res.json({ status: 'error', message: err });
                    return;
                }
                res.json({ status: 'ok', message: 'Register successfully' });
            }
        );
    });
});

app.post('/login', jsonParser, function (req, res, next) {
    connection.execute(
        'SELECT * FROM users WHERE email=? ',
        [req.body.email],
        function (err, users, fields) {
            if (err) { res.json({ status: 'error', message: err }); return }
            if (users.length == 0) { res.json({ status: 'error', message: 'no user found' }); return }
            bcrypt.compare(req.body.password, users[0].password, function (err, isLogin) {
                if (isLogin) {
                    // สร้าง token ที่มี userId, email และ role
                    const accessToken = jwt.sign(
                        { userId: users[0].userId, email: users[0].email, role: users[0].role },
                        secret,
                        { expiresIn: '1h' }
                    );
                    res.json({ status: 'ok', message: 'login success', accessToken: accessToken })
                } else {
                    res.json({ status: 'error', message: 'login failed' })
                }
            });
        }
    )
});

app.post('/admin-only-endpoint', authenticateToken, (req, res) => {
    if (req.user.role !== 'administration') {
        return res.status(403).json({ status: 'forbidden', message: 'Access denied' });
    }

    // Logic สำหรับผู้ใช้ที่มี role เป็น administration
    res.json({ status: 'ok', message: 'Welcome, admin!' });
});


app.post('/authen', jsonParser, function (req, res, next) {
    try {
        var token = req.headers.authorization.split(' ')[1]
        var decoded = jwt.verify(token, secret);
        res.json({ status: 'ok', decoded });
    } catch (err) {
        res.json({ status: 'error', message: err.message });
    }
})


app.get('/profile', authenticateToken, (req, res) => {
    connection.execute(
        'SELECT userId, fname, lname, email, image FROM users WHERE email = ?',
        [req.user.email],
        function (err, users, fields) {
            if (err) { res.json({ status: 'error', message: err }); return }
            if (users.length == 0) { res.json({ status: 'error', message: 'user not found' }); return }

            const user = {
                id: users[0].userId,
                fname: users[0].fname,
                lname: users[0].lname,
                email: users[0].email,
                image: users[0].image ? Buffer.from(users[0].image).toString('base64') : null

            };

            res.json({ status: 'ok', user });
        }
    );
});

app.get('/findAllBooking', (req, res) => {
    const sql = `
        SELECT 
            users.fname, 
            rooms.roomName
        FROM 
            bookings
        JOIN 
            users ON bookings.userId = users.userId
        JOIN 
            rooms ON bookings.roomId = rooms.roomId
        ORDER BY 
            users.fname;
    `;

    connection.query(sql, (err, results) => {
        if (err) throw err;
        res.json(results);
    });
});

app.get('/bookingDetail', authenticateToken, (req, res) => {

    if (!req.user || !req.user.email) {
        return res.status(400).json({ status: 'error', message: 'User ID not found in token' });
    }
    connection.execute(`
            SELECT  
                bookings.bookingNumber,
                rooms.roomName,
                rooms.roomType,
                bookings.checkIn,
                bookings.checkOut,
                bookings.Cost,
                bookings.adultsCount,
                bookings.childrenCount,
                bookings.duration,
                bookings.extraBed,
                bookings.bookingStatus
            FROM 
                bookings
            JOIN 
                users ON bookings.userId = users.userId
            JOIN 
                rooms ON bookings.roomId = rooms.roomId
            WHERE 
                users.email = ?`,
        [req.user.email],
        function (err, results, fields) {
            if (err) { res.json({ status: 'error', message: err }); return }
            if (results.length == 0) { res.json({ status: 'error', message: 'user not found' }); return }

            const booking = results.map(result => ({
                bookingNumber: result.bookingNumber,
                roomName: result.roomName,
                roomType: result.roomType,
                checkIn: result.checkIn,
                checkOut: result.checkOut,
                Cost: result.Cost,
                adultsCount: result.adultsCount,
                childrenCount: result.childrenCount,
                duration: result.duration,
                extraBed: result.extraBed,
                bookingStatus: result.bookingStatus
            }));

            res.json({ status: 'ok', booking });
        }
    )
})

const crypto = require('crypto');

function generateRandomBookingNumber(length) {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    const fixedPrefix = 'BBB';
    let result = fixedPrefix;
    const remainingLength = length - fixedPrefix.length;
    for (let i = 0; i < remainingLength; i++) {
        const randomIndex = Math.floor(Math.random() * charset.length);
        result += charset[randomIndex];
    }
    return result;
}
app.post('/booking', authenticateToken, (req, res) => {
    const { roomId, checkIn, checkOut, adultsCount, childrenCount, extraBed = false } = req.body;
    const userId = req.user.userId;
    const bookingNumber = generateRandomBookingNumber(8);

    if (!roomId || !checkIn || !checkOut || !adultsCount || !childrenCount) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    const checkInDate = new Date(checkIn);
    const checkOutDate = new Date(checkOut);

    if (checkOutDate < checkInDate) {
        return res.status(400).json({ error: 'Check-out date cannot be before check-in date' });
    }

    const isSameDay = checkInDate.toDateString() === checkOutDate.toDateString();
    if (isSameDay) {
        return res.status(400).json({ error: 'Check-out date cannot be the same as check-in date' });
    }

    const duration = Math.ceil((checkOutDate - checkInDate) / (1000 * 60 * 60 * 24));

    const checkAvailabilitySql = `
        SELECT * FROM bookings 
        WHERE roomId = ? 
        AND bookingStatus != "cancelled"
        AND ((checkIn <= ? AND checkOut >= ?) OR (checkIn <= ? AND checkOut >= ?))
    `;

    connection.query(checkAvailabilitySql, [roomId, checkOutDate, checkInDate, checkInDate, checkOutDate], (err, result) => {
        if (err) {
            console.error('Error checking room availability:', err);
            return res.status(500).json({ error: 'Failed to check room availability' });
        }

        if (result.length > 0) {
            return res.status(400).json({ error: 'Room is fully booked for the selected dates' });
        }

        const priceSql = 'SELECT roomPrice, descriptionPromotion FROM rooms WHERE roomId = ?';
        connection.query(priceSql, [roomId], (err, result) => {
            if (err) {
                console.error('Error fetching room price and promotion:', err);
                return res.status(500).json({ error: 'Failed to fetch room price and promotion' });
            }

            if (result.length === 0) {
                return res.status(404).json({ error: 'Room not found' });
            }

            const roomPrice = result[0].roomPrice;
            const descriptionPromotion = result[0].descriptionPromotion;
            let discount = 0;
            const regex = /Stay (\d+) Nights Extra Save (\d+)%/;
            const promotionMatch = descriptionPromotion.match(regex);

            if (promotionMatch) {
                const requiredNights = parseInt(promotionMatch[1], 10);
                const discountPercent = parseInt(promotionMatch[2], 10);
                if (duration >= requiredNights) {
                    discount = (discountPercent / 100) * (duration * roomPrice);
                }
            }

            const cost = (duration * roomPrice) - discount;

            const bookingSql = 'INSERT INTO bookings (bookingNumber, userId, roomId, checkIn, checkOut, adultsCount, childrenCount, duration, cost, extraBed, bookingStatus) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "pending")';
            connection.query(bookingSql, [bookingNumber, userId, roomId, checkIn, checkOut, adultsCount, childrenCount, duration, cost, extraBed], (err, result) => {
                if (err) {
                    console.error('Error inserting booking:', err);
                    return res.status(500).json({ error: 'Failed to book room' });
                }

                res.status(200).json({ status: 'ok', message: 'Room booked successfully', bookingNumber, cost });

                // Set timeout to delete pending bookings after 10 minutes
                setTimeout(() => {
                    const deleteSql = 'DELETE FROM bookings WHERE bookingNumber = ? AND bookingStatus = "pending"';
                    connection.query(deleteSql, [bookingNumber], (err, result) => {
                        if (err) {
                            console.error('Error deleting pending booking:', err);
                        } else if (result.affectedRows > 0) {
                            console.log(`Booking ${bookingNumber} has been deleted due to pending status for more than 10 minutes.`);
                        } else {
                            console.log(`No booking was deleted for bookingNumber ${bookingNumber}`);
                        }
                    });
                }, 10 * 60 * 1000); // 10 minutes
            });
        });
    });
});

app.post('/checkphoneNumber', jsonParser, (req, res) => {
    const phoneNumber = req.body.phoneNumber;  // ใช้ req.body สำหรับ POST requests

    if (!phoneNumber) {
        return res.status(400).json({ status: 'error', message: 'phoneNumber parameter is required.' });
    }
    // กำหนดรูปแบบอีเมลที่ถูกต้อง
    const phoneNumberPattern = /^0[689]\d{8}$/;

    if (!phoneNumberPattern.test(phoneNumber)) {
        return res.status(400).json({ status: 'error', message: 'Invalid phoneNumber format.' });
    }

    const sql = 'SELECT * FROM users WHERE phone_number = ?';
    connection.query(sql, [phoneNumber], (err, results) => {
        if (err) {
            console.error('Database query error:', err);
            return res.status(500).json({ status: 'error', message: 'Database query failed.' });
        }

        if (results.length > 0) {
            return res.json({ exists: true });  // If email is found
        } else {
            return res.json({ exists: false });  // If email is not found
        }
    });
});









// const dns = require('dns');

// function checkEmailExists(email, callback) {
//     const domain = email.split('@')[1];
//     dns.resolveMx(domain, (err, addresses) => {
//         if (err || addresses.length === 0) {
//             callback(false);
//         } else {
//             callback(true);
//         }
//     });
// }
// app.post('/checkDns', jsonParser, (req, res) => {
//     const email = req.body.email;
//     if (!email) {
//         return res.status(400).json({ status: 'error', message: 'Email parameter is required.' });
//     }
//     checkEmailExists(email, (exists) => {
//         if (exists) {
//             res.json({ exists: true });
//         } else {
//             res.json({ exists: false });
//         }
//     });
// });

app.post('/checkEmail', jsonParser, (req, res) => {
    const email = req.body.email;  // ใช้ req.body สำหรับ POST requests

    if (!email) {
        return res.status(400).json({ status: 'error', message: 'Email parameter is required.' });
    }
    // กำหนดรูปแบบอีเมลที่ถูกต้อง
    const emailPattern = /^[A-Za-z][A-Za-z0-9.-_+-]*@(gmail\.com|hotmail\.com)$/;

    if (!emailPattern.test(email)) {
        return res.status(400).json({ status: 'error', message: 'Invalid email format. Email must start with a letter and contain only letters and numbers.' });
    }

    const sql = 'SELECT * FROM users WHERE email = ?';
    connection.query(sql, [email], (err, results) => {
        if (err) {
            console.error('Database query error:', err);
            return res.status(500).json({ status: 'error', message: 'Database query failed.' });
        }

        if (results.length > 0) {
            return res.json({ exists: true });  // If email is found
        } else {
            return res.json({ exists: false });  // If email is not found
        }
    });
});


app.listen(3333, function () {
    console.log('CORS-enabled web server listening on port 3333')
})

