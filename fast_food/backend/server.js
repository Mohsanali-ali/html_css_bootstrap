const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// Database connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'fast_food'
});

db.connect((err) => {
    if (err) {
        console.error('Database connection failed:', err);
        return;
    }
    console.log('Connected to MySQL database');
});

// Email transporter
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// Routes

// User registration
app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        db.query(
            'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
            [name, email, hashedPassword],
            (err, result) => {
                if (err) {
                    if (err.code === 'ER_DUP_ENTRY') {
                        return res.status(400).json({ error: 'Email already exists' });
                    }
                    return res.status(500).json({ error: 'Database error' });
                }

                const token = jwt.sign(
                    { userId: result.insertId, email, role: 'customer' },
                    process.env.JWT_SECRET,
                    { expiresIn: '24h' }
                );

                res.json({
                    message: 'User registered successfully',
                    token,
                    user: { id: result.insertId, name, email, role: 'customer' }
                });
            }
        );
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// User login
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    db.query(
        'SELECT * FROM users WHERE email = ?',
        [email],
        async (err, results) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }

            if (results.length === 0) {
                return res.status(400).json({ error: 'Invalid credentials' });
            }

            const user = results[0];

            try {
                const validPassword = await bcrypt.compare(password, user.password);
                if (!validPassword) {
                    return res.status(400).json({ error: 'Invalid credentials' });
                }

                const token = jwt.sign(
                    { userId: user.id, email: user.email, role: user.role },
                    process.env.JWT_SECRET,
                    { expiresIn: '24h' }
                );

                res.json({
                    message: 'Login successful',
                    token,
                    user: { id: user.id, name: user.name, email: user.email, role: user.role }
                });
            } catch (error) {
                res.status(500).json({ error: 'Server error' });
            }
        }
    );
});

// Get menu items
app.get('/api/menu', (req, res) => {
    db.query('SELECT * FROM menu_items WHERE is_available = true', (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        res.json(results);
    });
});

// Create order
app.post('/api/orders', authenticateToken, (req, res) => {
    const { items, customer_name, customer_email, customer_phone, special_instructions, total_amount } = req.body;

    db.query(
        'INSERT INTO orders (user_id, customer_name, customer_email, customer_phone, special_instructions, total_amount) VALUES (?, ?, ?, ?, ?, ?)',
        [req.user.userId, customer_name, customer_email, customer_phone, special_instructions, total_amount],
        (err, result) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }

            const orderId = result.insertId;
            const orderItems = items.map(item => [orderId, item.id, item.quantity, item.price]);

            db.query(
                'INSERT INTO order_items (order_id, menu_item_id, quantity, price) VALUES ?',
                [orderItems],
                (err) => {
                    if (err) {
                        return res.status(500).json({ error: 'Database error' });
                    }

                    res.json({
                        message: 'Order placed successfully',
                        orderId
                    });
                }
            );
        }
    );
});

// Get orders (Admin only)
app.get('/api/admin/orders', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }

    const query = `
        SELECT o.*, u.name as user_name 
        FROM orders o 
        LEFT JOIN users u ON o.user_id = u.id 
        ORDER BY o.created_at DESC
    `;

    db.query(query, (err, orders) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        // Get order items for each order
        const orderIds = orders.map(order => order.id);
        if (orderIds.length === 0) {
            return res.json([]);
        }

        const itemsQuery = `
            SELECT oi.*, mi.name as item_name 
            FROM order_items oi 
            JOIN menu_items mi ON oi.menu_item_id = mi.id 
            WHERE oi.order_id IN (?)
        `;

        db.query(itemsQuery, [orderIds], (err, orderItems) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }

            // Group items by order_id
            const itemsByOrder = orderItems.reduce((acc, item) => {
                if (!acc[item.order_id]) {
                    acc[item.order_id] = [];
                }
                acc[item.order_id].push(item);
                return acc;
            }, {});

            // Add items to orders
            const ordersWithItems = orders.map(order => ({
                ...order,
                items: itemsByOrder[order.id] || []
            }));

            res.json(ordersWithItems);
        });
    });
});

// Update order status and send email
app.put('/api/admin/orders/:id/status', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }

    const { status } = req.body;
    const orderId = req.params.id;

    db.query(
        'UPDATE orders SET status = ? WHERE id = ?',
        [status, orderId],
        async (err, result) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }

            // Get order details for email
            db.query(
                'SELECT customer_email, customer_name, total_amount FROM orders WHERE id = ?',
                [orderId],
                async (err, orders) => {
                    if (err || orders.length === 0) {
                        return res.json({ message: 'Order status updated' });
                    }

                    const order = orders[0];

                    // Send email notification
                    try {
                        await transporter.sendMail({
                            from: process.env.EMAIL_USER,
                            to: order.customer_email,
                            subject: `Order #${orderId} Status Update - Flavor Feast`,
                            html: `
                                <h2>Hello ${order.customer_name}!</h2>
                                <p>Your order #${orderId} has been <strong>${status}</strong>.</p>
                                <p>Total Amount: Rs. ${order.total_amount}</p>
                                <p>We'll notify you when your order is ready for delivery.</p>
                                <br>
                                <p>Thank you for choosing Flavor Feast!</p>
                            `
                        });
                    } catch (emailError) {
                        console.error('Email sending failed:', emailError);
                    }

                    res.json({ message: 'Order status updated and notification sent' });
                }
            );
        }
    );
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});