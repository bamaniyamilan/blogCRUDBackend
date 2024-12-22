const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('Connected to MongoDB Atlas'))
  .catch((err) => console.error('Failed to connect to MongoDB Atlas:', err));


const User = mongoose.model(
  'User',
  new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    posts: [
      {
        title: { type: String, required: true },
        description: { type: String, required: true },
      },
    ],
  })
);

// Middleware to authenticate JWT tokens
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).send({ message: 'Unauthorized' });

  try {
    const decoded = jwt.verify(token, 'secretKey');
    req.userId = decoded.id;
    next();
  } catch (err) {
    res.status(403).send({ message: 'Invalid token' });
  }
};

// Register route
app.post('/api/register', async (req, res) => {
  const { name, email, password, confirmPassword } = req.body;

  if (password !== confirmPassword) {
    return res.status(400).send({ message: 'Passwords do not match' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ name, email, password: hashedPassword, posts: [] });
  try {
    await user.save();
    res.send({ message: 'User registered successfully' });
  } catch (err) {
    res.status(400).send({ message: 'Error registering user', error: err.message });
  }
});

// Login route
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.status(404).send({ message: 'User not found' });

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) return res.status(401).send({ message: 'Invalid credentials' });

  const token = jwt.sign({ id: user._id }, 'secretKey', { expiresIn: '1h' });
  res.send({ message: 'Login successful', token });
});

// Get user information (after login)
app.get('/api/user', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('name email'); // Select only name and email fields
    if (!user) return res.status(404).send({ message: 'User not found' });

    res.send(user);
  } catch (err) {
    res.status(500).send({ message: 'Server error', error: err.message });
  }
});

// Create a post
app.post('/api/posts', authenticate, async (req, res) => {
  const { title, description } = req.body;

  const user = await User.findById(req.userId);
  if (!user) return res.status(404).send({ message: 'User not found' });

  user.posts.push({ title, description });
  await user.save();

  res.send({ message: 'Post created successfully', posts: user.posts });
});

// Get all posts of the logged-in user
app.get('/api/posts', authenticate, async (req, res) => {
  const user = await User.findById(req.userId);
  if (!user) return res.status(404).send({ message: 'User not found' });

  res.send(user.posts);
});

// Update a post
app.put('/api/posts/:postId', authenticate, async (req, res) => {
  const { title, description } = req.body;

  const user = await User.findById(req.userId);
  if (!user) return res.status(404).send({ message: 'User not found' });

  const post = user.posts.id(req.params.postId);
  if (!post) return res.status(404).send({ message: 'Post not found' });

  post.title = title;
  post.description = description;
  await user.save();

  res.send({ message: 'Post updated successfully', posts: user.posts });
});

// Delete a post
app.delete('/api/posts/:postId', authenticate, async (req, res) => {
  const user = await User.findById(req.userId);
  if (!user) return res.status(404).send({ message: 'User not found' });

  user.posts = user.posts.filter((post) => post._id.toString() !== req.params.postId);
  await user.save();

  res.send({ message: 'Post deleted successfully', posts: user.posts });
});

// Start the server
const PORT = 4000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
