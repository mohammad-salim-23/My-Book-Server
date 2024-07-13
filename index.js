const express = require("express");
const app = express();
const jwt = require('jsonwebtoken');
require("dotenv").config();
const cors = require("cors");
const helmet = require("helmet");

const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(helmet({
  crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" }
}));

const { MongoClient, ServerApiVersion } = require('mongodb');
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.ipsrkdy.mongodb.net/?appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    // Connect the client to the server (optional starting in v4.7)
    await client.connect();
    const userCollection = client.db("bookDB").collection("users");
    const bookCollection = client.db("bookDB").collection("books");

    // Middleware to verify token
    const verifyToken = (req, res, next) => {
        console.log("Inside verify token", req.headers);
        if (!req.headers.authorization) {
            return res.status(401).send({ message: "Unauthorized access" });
        }
        const token = req.headers.authorization.split(' ')[1];
        jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
            if (err) {
                return res.status(401).send({ message: "Unauthorized access" });
            }
            req.decoded = decoded;
            next();
        });
    };

    // Middleware to verify admin
    const verifyAdmin = async (req, res, next) => {
        const email = req.decoded.email;
        const query = { email: email };
        const user = await userCollection.findOne(query);
        const isAdmin = user?.role === 'admin';
        if (!isAdmin) {
            return res.status(403).send({ message: 'Forbidden access' });
        }
        next();
    };

    // JWT related API
    app.post("/jwt", async (req, res) => {
        const user = req.body;
        console.log("JWT...", user);
        const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' });
        res.send({ token });
    });

    // Users related API
    app.post("/users", async (req, res) => {
        const user = req.body;
        // Insert email if user doesn't exist
        const query = { email: user.email };
        const existingUser = await userCollection.findOne(query);
        if (existingUser) {
            console.log(existingUser);
            return res.send({ message: 'User already exists', insertedId: null });
        }
        const result = await userCollection.insertOne(user);
        res.send(result);
    });
    app.get('/users/admin/:email',verifyToken,async(req,res)=>{
      const email = req.params.email;
      if(email!==req.decoded?.email){
        return res.status(403).send({message:'forbidden  access one'});
      }
      const query = {email:email};
      const user = await userCollection.findOne(query);
      let admin = false;
      if(user){
        admin = user?.role==='admin'
      }
      res.send({admin});
    })
    // book related api
    app.post('/addBook',verifyToken,async(req,res)=>{
      const book = req.body;
      const email = req.params.email;
      const result = await bookCollection.insertOne(book);
      res.send(result);
    })

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}

run().catch(console.dir);

app.get('/', (req, res) => {
    res.send("My-Book is running");
});

app.listen(port, () => {
    console.log(`MyBook is running on port ${port}`);
});
