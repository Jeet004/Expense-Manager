const express = require('express');
const db = require('./db'); // Your MySQL connection
const bodyParser = require('body-parser');
const expressLayouts = require('express-ejs-layouts');
const flash = require('connect-flash');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');
const app = express();

const categoryMapping = {
    'Food': 'Food & Dining',
    'Housing & Rent': 'Housing',
    'Transport': 'Transportation'
};

// Body-parser middleware to handle JSON and URL-encoded data
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// View setup
app.set('views', path.join(__dirname, 'views'));
// EJS setup
app.set('view engine', 'ejs');
app.use(expressLayouts);
app.set('layout', 'layouts/layout');

// Middleware setup
app.use(express.static('public'));
app.use(expressLayouts);

// Session setup
app.use(session({
    secret: 'finance-manager-secret',
    resave: false,
    saveUninitialized: false
}));

// Flash setup
app.use(flash());

// Passport setup
app.use(passport.initialize());
app.use(passport.session());

// Global variables for flash messages
app.use((req, res, next) => {
    res.locals.success_msg = req.flash('success_msg');
    res.locals.error_msg = req.flash('error_msg');
    res.locals.error = req.flash('error');
    res.locals.title = 'Finance Manager'; // Default title
    res.locals.user = req.user || null; // Add this line to make user available to all views
    next();
});

// Middleware to protect routes
const ensureAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) return next();
    req.flash('error_msg', 'Please log in to view that resource');
    res.redirect('/login');
};

// Set up session and passport
app.use(session({
    secret: 'finance-manager-secret',
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

// Passport strategy for login
passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
    try {
        const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length === 0) {
            return done(null, false, { message: 'Incorrect email.' });
        }
        const user = rows[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (isMatch) {
            return done(null, user);
        } else {
            return done(null, false, { message: 'Incorrect password.' });
        }
    } catch (err) {
        return done(err);
    }
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const [rows] = await db.query('SELECT * FROM users WHERE id = ?', [id]);
        if (rows.length === 0) {
            return done(null, false);
        }
        return done(null, rows[0]);
    } catch (err) {
        return done(err);
    }
});

// Helper function to calculate income, expenses, and balance
const calculateFinances = (transactions) => {
    if (!Array.isArray(transactions)) {
        return { income: 0, expenses: 0, balance: 0 };  // Default values if transactions is not an array
    }

    const income = transactions.filter(t => t.type === 'income').reduce((sum, t) => sum + parseFloat(t.amount), 0);
    const expenses = transactions.filter(t => t.type === 'expense').reduce((sum, t) => sum + parseFloat(t.amount), 0);
    const balance = income - expenses;
    return { income, expenses, balance };
};

// Home Page (Protected)
// Home Page (Dashboard) Route
app.get('/', ensureAuthenticated, async (req, res) => {
    let query = 'SELECT * FROM transactions WHERE user_id = ?';
    let params = [req.user.id];

    if (req.query.startDate && req.query.endDate) {
        query += ' AND date BETWEEN ? AND ?';
        params.push(req.query.startDate, req.query.endDate);
    }

    // Debug logging
    console.log('Dashboard SQL:', query);
    console.log('Dashboard Params:', params);

    try {
        const [transactions] = await db.query(query, params);
        const { income, expenses, balance } = calculateFinances(transactions);
        res.render('index', { title: 'Dashboard', transactions, income, expenses, balance });
    } catch (err) {
        console.error(err);
        res.redirect('/login');
    }
});

// Add Transaction Page (Protected)
app.get('/add', ensureAuthenticated, (req, res) => {
    // Define a standardized list of categories
    const categories = [
        'Food & Dining', 'Transportation', 'Housing', 'Utilities', 'Healthcare', 
        'Entertainment', 'Shopping', 'Education', 'Bills & Payments', 'Insurance', 
        'Travel', 'Groceries', 'Personal Care', 'Gifts & Donations', 
        'Business Expenses', 'Other Expenses'
    ];

    // Render the addTransaction page with the standardized categories
    res.render('addtransaction', { title: 'Add Transaction', categories });
});

// Add Transaction (POST) (Protected)
app.post('/add', ensureAuthenticated, async (req, res) => {
    const { type, amount, date, description, category } = req.body;
    const userId = req.user.id;

    if (!type || !amount || !date || !description || !category) {
        req.flash('error', 'All fields are required.');
        return res.redirect('/add');
    }

    try {
        const query = 'INSERT INTO transactions (user_id, type, amount, date, description, category) VALUES (?, ?, ?, ?, ?, ?)';
        await db.execute(query, [userId, type, amount, date, description, category]);
        req.flash('success', 'Transaction added successfully!');
        res.redirect('/');
    } catch (err) {
        console.error('Error adding transaction:', err);
        req.flash('error', 'Failed to add transaction.');
        res.redirect('/add');
    }
});

function getCategoriesSummary(transactions) {
    const categorySummary = {};

    transactions.forEach(t => {
        let category = t.category;
        if (categoryMapping[category]) {
            category = categoryMapping[category];
        }

        const amount = parseFloat(t.amount);

        if (category) {
            if (!categorySummary[category]) {
                categorySummary[category] = 0;
            }
            categorySummary[category] += amount;
        }
    });

    return Object.keys(categorySummary).map(category => ({
        name: category,
        total: categorySummary[category]
    }));
}

// Summary Page (Protected)
// Summary Page Route
app.get('/summary', ensureAuthenticated, async (req, res) => {
    try {
        // Fetch all transactions for cards and tables
        let allTransactionQuery = 'SELECT * FROM transactions WHERE user_id = ?';
        let allTransactionParams = [req.user.id];
        if (req.query.startDate && req.query.endDate) {
            allTransactionQuery += ' AND date BETWEEN ? AND ?';
            allTransactionParams.push(req.query.startDate, req.query.endDate);
        }
        const [allTransactions] = await db.query(allTransactionQuery, allTransactionParams);

        // Fetch only expense transactions for the pie chart
        let expenseTransactionQuery = 'SELECT * FROM transactions WHERE user_id = ? AND type = "expense"';
        let expenseTransactionParams = [req.user.id];
        if (req.query.startDate && req.query.endDate) {
            expenseTransactionQuery += ' AND date BETWEEN ? AND ?';
            expenseTransactionParams.push(req.query.startDate, req.query.endDate);
        }
        const [expenseTransactions] = await db.query(expenseTransactionQuery, expenseTransactionParams);

        // Calculate income, expenses, balance from all transactions
        const { income, expenses, balance } = calculateFinances(allTransactions);

        // Get categories summary for all transactions (for table)
        const categories = getCategoriesSummary(allTransactions);

        // Prepare expenseData for pie chart (only expenses)
        const expenseCategories = getCategoriesSummary(expenseTransactions);
        const expenseDataForPie = expenseCategories.map(cat => ({
            category: cat.name,
            total: cat.total
        }));

        // --- Logic for Bar Chart ---
        const barChartData = { labels: [], budget: [], actual: [] };
        if (req.query.barChartMonth) {
            const [year, month] = req.query.barChartMonth.split('-');

            // 1. Get budgets for the selected month and normalize
            const [rawBudgets] = await db.query(
                'SELECT category, amount FROM budgets WHERE user_id = ? AND month = ? AND year = ?',
                [req.user.id, parseInt(month, 10), parseInt(year, 10)]
            );
            const budgetMap = new Map();
            rawBudgets.forEach(item => {
                const category = categoryMapping[item.category] || item.category;
                budgetMap.set(category, (budgetMap.get(category) || 0) + parseFloat(item.amount || 0));
            });

            // 2. Get actual expenses for the selected month and normalize
            const firstDay = new Date(year, month - 1, 1);
            const lastDay = new Date(year, month, 0);
            const [rawExpenses] = await db.query(
                `SELECT category, SUM(amount) as total FROM transactions 
                 WHERE user_id = ? AND type = 'expense' AND date BETWEEN ? AND ? 
                 GROUP BY category`,
                [req.user.id, firstDay, lastDay]
            );
            const expenseMap = new Map();
            rawExpenses.forEach(item => {
                const category = categoryMapping[item.category] || item.category;
                expenseMap.set(category, (expenseMap.get(category) || 0) + parseFloat(item.total || 0));
            });
            
            // 3. Create a unified data structure
            const allCats = [...new Set([...budgetMap.keys(), ...expenseMap.keys()])];
            barChartData.labels = allCats;
            barChartData.budget = allCats.map(cat => budgetMap.get(cat) || 0);
            barChartData.actual = allCats.map(cat => expenseMap.get(cat) || 0);
        }

        res.render('summary', {
            title: 'Summary - Personal Finance',
            transactions: allTransactions,
            income,
            expenses,
            balance,
            categories,
            expenseData: expenseDataForPie, // For pie chart
            barChartData, // For bar chart
            startDate: req.query.startDate || '',
            endDate: req.query.endDate || '',
            barChartMonth: req.query.barChartMonth || ''
        });
    } catch (err) {
        console.error(err);
        res.redirect('/');
    }
});

// About Page (Protected)
app.get('/about', ensureAuthenticated, (req, res) => {
    res.render('about', { title: 'About' });
});

// Login Page
app.get('/login', (req, res) => {
    res.render('login', { title: 'Login' });
});

// Login POST Route
app.post('/login', (req, res, next) => {
    passport.authenticate('local', {
        successRedirect: '/',
        failureRedirect: '/login',
        failureFlash: true // Enable flash messages on failure
    })(req, res, next);
});

// Sign Up Page
app.get('/signup', (req, res) => {
    res.render('signup', { title: 'Sign Up' });
});

// Sign Up (POST)
app.post('/signup', async (req, res) => {
    const { name, email, password } = req.body;
    try {
        const [existing] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
        if (existing.length > 0) {
            req.flash('error_msg', 'Email already registered');
            return res.redirect('/signup');
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await db.query('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [name, email, hashedPassword]);

        req.flash('success_msg', 'Registration successful! Please login.');
        res.redirect('/login');
    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Error during registration');
        res.redirect('/signup');
    }
});

// Logout
app.get('/logout', (req, res) => {
    req.logout((err) => {
        res.redirect('/');
    });
});

// Budget Planning Page (Protected)
app.get('/budget', ensureAuthenticated, async (req, res) => {
    try {
        // Step 1: Get all unique, normalized categories from transactions
        const [allCategoriesFromDb] = await db.query(
            'SELECT DISTINCT category FROM transactions WHERE user_id = ? AND type = "expense"',
            [req.user.id]
        );
        const categories = [...new Set(allCategoriesFromDb.map(cat => categoryMapping[cat.category] || cat.category))];
        
        // Step 2: Get budget data and normalize it
        const [rawBudgetData] = await db.query('SELECT category, amount FROM budgets WHERE user_id = ?', [req.user.id]);
        const budgetMap = new Map();
        rawBudgetData.forEach(item => {
            const category = categoryMapping[item.category] || item.category;
            const amount = parseFloat(item.amount || 0);
            budgetMap.set(category, (budgetMap.get(category) || 0) + amount);
        });

        // Step 3: Get expense data and normalize it
        const [rawExpenseData] = await db.query(
            'SELECT category, SUM(amount) as total FROM transactions WHERE user_id = ? AND type = "expense" GROUP BY category',
            [req.user.id]
        );
        const expenseMap = new Map();
        rawExpenseData.forEach(item => {
            const category = categoryMapping[item.category] || item.category;
            const total = parseFloat(item.total || 0);
            expenseMap.set(category, (expenseMap.get(category) || 0) + total);
        });

        // Step 4: Combine all categories from budgets and expenses
        const allUniqueCategories = [...new Set([...categories, ...budgetMap.keys(), ...expenseMap.keys()])];

        // Step 5: Build the final display data
        const budgetDisplayData = allUniqueCategories.map(category => {
            const budget = budgetMap.get(category) || 0;
            const spent = expenseMap.get(category) || 0;
            const remaining = Math.max(0, budget - spent);
            const percentage = budget > 0 ? (spent / budget * 100) : 0;
            return {
                category,
                budget,
                spent,
                remaining,
                progress: {
                    percentage: Math.min(100, percentage).toFixed(1),
                    color: percentage > 90 ? 'bg-danger' : percentage > 75 ? 'bg-warning' : 'bg-success'
                }
            };
        });

        res.render('budget', { 
            title: 'Budget Planning',
            categories: allUniqueCategories, // For the dropdown
            budgetDisplayData: budgetDisplayData // For the table
        });
    } catch (err) {
        console.error(err);
        res.redirect('/');
    }
});

// Set Budget (Protected)
app.post('/budget/set', ensureAuthenticated, async (req, res) => {
    const { category, amount, budgetMonth } = req.body;
    console.log('Budget form submission:', req.body);
    try {
        // Parse month and year from budgetMonth (format: YYYY-MM)
        const [year, month] = budgetMonth ? budgetMonth.split('-') : [null, null];
        console.log('Parsed year:', year, 'Parsed month:', month);
        // Use REPLACE INTO to handle both insert and update
        await db.query(
            'REPLACE INTO budgets (user_id, category, amount, month, year) VALUES (?, ?, ?, ?, ?)',
            [req.user.id, category, amount, parseInt(month), parseInt(year)]
        );
        req.flash('success_msg', 'Budget updated successfully');
        res.redirect('/budget');
    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Error updating budget');
        res.redirect('/budget');
    }
});

// API endpoint for getting budget data
app.get('/api/budget-data', ensureAuthenticated, async (req, res) => {
    try {
        const normalizeAndAggregate = (items, categoryKey, valueKey) => {
            const summary = {};
            items.forEach(item => {
                let category = item[categoryKey];
                if (categoryMapping[category]) {
                    category = categoryMapping[category];
                }
                if (category) {
                    if (!summary[category]) {
                        summary[category] = 0;
                    }
                    summary[category] += parseFloat(item[valueKey] || 0);
                }
            });
            return Object.keys(summary).map(category => ({
                category: category,
                [valueKey]: summary[category]
            }));
        };

        // Get budget data from database
        const [rawBudgets] = await db.query('SELECT category, amount FROM budgets WHERE user_id = ?', [req.user.id]);
        const budgets = normalizeAndAggregate(rawBudgets, 'category', 'amount');
        
        // Get expense data from database, filtered by date if provided
        let expenseQuery = 'SELECT category, SUM(amount) as total FROM transactions WHERE user_id = ? AND type = "expense"';
        let expenseParams = [req.user.id];
        if (req.query.startDate && req.query.endDate) {
            expenseQuery += ' AND date BETWEEN ? AND ?';
            expenseParams.push(req.query.startDate, req.query.endDate);
        }
        expenseQuery += ' GROUP BY category';
        const [rawExpenses] = await db.query(expenseQuery, expenseParams);
        const expenses = normalizeAndAggregate(rawExpenses, 'category', 'total');

        // Create a unified list of categories from both budgets and expenses
        const allCategories = [...new Set([
            ...budgets.map(b => b.category),
            ...expenses.map(e => e.category)
        ])];

        // Transform the data into the required format
        const expenseData = {
            labels: expenses.map(expense => expense.category),
            data: expenses.map(expense => parseFloat(expense.total))
        };

        const budgetData = {
            labels: allCategories,
            budget: allCategories.map(cat => {
                const budgetItem = budgets.find(b => b.category === cat);
                return budgetItem ? parseFloat(budgetItem.amount) : 0;
            }),
            actual: allCategories.map(cat => {
                const expenseItem = expenses.find(e => e.category === cat);
                return expenseItem ? parseFloat(expenseItem.total) : 0;
            })
        };

        res.json({
            expenseData,
            budgetData
        });
    } catch (error) {
        console.error('Error fetching budget data:', error);
        res.status(500).json({ error: 'Failed to fetch budget data' });
    }
});

// Careers Page
app.get('/careers', (req, res) => {
    res.render('careers');
});

// Settings Page
app.get('/settings', (req, res) => {
    res.render('settings', { title: 'Settings', user: req.user });
});

// Update Profile (POST)
app.post('/settings/profile', ensureAuthenticated, async (req, res) => {
    const { name, email } = req.body;
    try {
        // Check if email is already used by another user
        const [existing] = await db.query('SELECT * FROM users WHERE email = ? AND id != ?', [email, req.user.id]);
        if (existing.length > 0) {
            req.flash('error_msg', 'Email already in use by another account.');
            return res.redirect('/settings');
        }
        await db.query('UPDATE users SET name = ?, email = ? WHERE id = ?', [name, email, req.user.id]);
        req.flash('success_msg', 'Profile updated successfully.');
        // Update session user
        req.user.name = name;
        req.user.email = email;
        res.redirect('/settings');
    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Error updating profile.');
        res.redirect('/settings');
    }
});

// Change Password (POST)
app.post('/settings/password', ensureAuthenticated, async (req, res) => {
    const { currentPassword, newPassword, confirmPassword } = req.body;
    try {
        // Get current user
        const [rows] = await db.query('SELECT * FROM users WHERE id = ?', [req.user.id]);
        const user = rows[0];
        // Check current password
        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            req.flash('error_msg', 'Current password is incorrect.');
            return res.redirect('/settings');
        }
        // Check new password confirmation
        if (newPassword !== confirmPassword) {
            req.flash('error_msg', 'New passwords do not match.');
            return res.redirect('/settings');
        }
        // Hash new password and update
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await db.query('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, req.user.id]);
        req.flash('success_msg', 'Password changed successfully.');
        res.redirect('/settings');
    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Error changing password.');
        res.redirect('/settings');
    }
});

// Route to render the reports page
app.get('/reports', ensureAuthenticated, (req, res) => {
    res.render('reports', { title: 'Financial Reports' });
});

// API endpoint to generate report data
app.post('/api/reports', ensureAuthenticated, async (req, res) => {
    try {
        const { reportType, month, year, startDate, endDate } = req.body;
        const userId = req.user.id; // Correctly use the logged-in user's ID

        // --- Start of Diagnostic Logging ---
        console.log('[REPORTING] Received request:', req.body);
        console.log('[REPORTING] User ID:', userId);
        // --- End of Diagnostic Logging ---

        let data = {};

        if (reportType === 'monthly') {
            if (!month) {
                return res.status(400).json({ success: false, message: 'Month is required for monthly report.' });
            }
            // `month` is in 'YYYY-MM' format
            const a_year = month.split('-')[0];
            const a_month = month.split('-')[1];

            const firstDay = new Date(a_year, a_month - 1, 1);
            const lastDay = new Date(a_year, a_month, 0);

            // 1. Get summary (income, expenses, savings)
            const [summary] = await db.execute(
                `SELECT 
                    SUM(CASE WHEN type = 'income' THEN amount ELSE 0 END) as totalIncome,
                    SUM(CASE WHEN type = 'expense' THEN amount ELSE 0 END) as totalExpense
                 FROM transactions 
                 WHERE user_id = ? AND date BETWEEN ? AND ?`,
                [userId, firstDay, lastDay]
            );
            const totalIncome = summary[0].totalIncome || 0;
            const totalExpense = summary[0].totalExpense || 0;

            // 2. Get expense distribution by category
            const [expenseDistribution] = await db.execute(
                `SELECT category, SUM(amount) as total 
                 FROM transactions 
                 WHERE user_id = ? AND type = 'expense' AND date BETWEEN ? AND ? 
                 GROUP BY category ORDER BY total DESC`,
                [userId, firstDay, lastDay]
            );

            // 3. Get all transactions for the period
            const [transactions] = await db.execute(
                `SELECT * FROM transactions WHERE user_id = ? AND date BETWEEN ? AND ? ORDER BY date DESC`,
                [userId, firstDay, lastDay]
            );

            data = {
                summary: {
                    totalIncome: parseFloat(totalIncome),
                    totalExpense: parseFloat(totalExpense),
                    netSavings: parseFloat(totalIncome) - parseFloat(totalExpense)
                },
                expenseDistribution,
                transactions
            };
        } else if (reportType === 'yearly') {
            if (!year) {
                return res.status(400).json({ success: false, message: 'Year is required for yearly report.' });
            }

            const [monthlyTrends] = await db.execute(
                `SELECT 
                    MONTH(date) as monthNum,
                    SUM(CASE WHEN type = 'income' THEN amount ELSE 0 END) as totalIncome,
                    SUM(CASE WHEN type = 'expense' THEN amount ELSE 0 END) as totalExpense
                 FROM transactions 
                 WHERE user_id = ? AND YEAR(date) = ? 
                 GROUP BY MONTH(date) 
                 ORDER BY monthNum ASC`,
                [userId, year]
            );

            // Initialize 12 months with 0 values
            const months = Array.from({ length: 12 }, (_, i) => ({
                month: new Date(0, i).toLocaleString('default', { month: 'long' }),
                totalIncome: 0,
                totalExpense: 0,
            }));

            // Populate with data from the database
            monthlyTrends.forEach(row => {
                months[row.monthNum - 1].totalIncome = parseFloat(row.totalIncome);
                months[row.monthNum - 1].totalExpense = parseFloat(row.totalExpense);
            });

            data = { monthlyTrends: months };
        } else if (reportType === 'range') {
            if (!startDate || !endDate) {
                return res.status(400).json({ success: false, message: 'Start and end dates are required for range report.' });
            }

            // 1. Get summary
            const [summary] = await db.execute(
                `SELECT 
                    SUM(CASE WHEN type = 'income' THEN amount ELSE 0 END) as totalIncome,
                    SUM(CASE WHEN type = 'expense' THEN amount ELSE 0 END) as totalExpense
                 FROM transactions 
                 WHERE user_id = ? AND date BETWEEN ? AND ?`,
                [userId, startDate, endDate]
            );
            const totalIncome = summary[0].totalIncome || 0;
            const totalExpense = summary[0].totalExpense || 0;

            // 2. Get expense distribution
            const [expenseDistribution] = await db.execute(
                `SELECT category, SUM(amount) as total 
                 FROM transactions 
                 WHERE user_id = ? AND type = 'expense' AND date BETWEEN ? AND ? 
                 GROUP BY category ORDER BY total DESC`,
                [userId, startDate, endDate]
            );

            // 3. Get all transactions
            const [transactions] = await db.execute(
                `SELECT * FROM transactions WHERE user_id = ? AND date BETWEEN ? AND ? ORDER BY date DESC`,
                [userId, startDate, endDate]
            );

            data = {
                summary: {
                    totalIncome: parseFloat(totalIncome),
                    totalExpense: parseFloat(totalExpense),
                    netSavings: parseFloat(totalIncome) - parseFloat(totalExpense)
                },
                expenseDistribution,
                transactions
            };
        }

        // --- Diagnostic Logging for Response ---
        console.log('[REPORTING] Sending data:', JSON.stringify(data, null, 2));
        // --- End of Diagnostic Logging ---

        res.json({ success: true, data });

    } catch (err) {
        console.error('Error generating report:', err);
        res.status(500).json({ success: false, message: 'Server error while generating report.' });
    }
});

// Start Server
app.listen(3001, () => {
    console.log('Server running on http://localhost:3001');
});
