const express = require("express");
const app = express();
const jwt = require('jsonwebtoken');
require("dotenv").config();
const cors = require("cors");

const port = process.env.PORT ||5000;

// middleware
app.use(cors());
app.use(express.json());

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
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();
    const userCollection = client.db("bookDB").collection("users");
    const bookCollection = client.db("bookDB").collection("books");

    // middleWare
    
    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}

app.get('/',(req,res)=>{
    res.send("My-BOOk is running");
})
app.listen(port,()=>{
    console.log(`MyBook is running on port ${port}`);
})

