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
    const verifyToken = (req,res,next)=>{
        console.log("inside verify token",req.headers);
        if(!req.headers.authorization){
            return res.status(401).send(
                {message:"unauthorized access"}
            )
        }
        const token = req.headers.authorization.split('')[1];
        jwt.verify(token,process.env.ACCESS_TOKEN_SECRET,(err,decoded)=>{
            if(err){
                return res.status(401).send({
                    message:"unauthorized access"
                })
            }
            req.decoded = decoded;
            next();
        })
    }
    // use verify admin after 
    const verifyAdmin = async(req,res,next)=>{
        const email = req.decoded.email;
        const query = {email:email};
        const user = await userCollection.findOne(query);
        const isAdmin = user?.role==='admin';
        if(!isAdmin){
          return res.status(403).send({message:'forbidden access true'});
        }
        next();
       }
    //    jwt related api
    app.post("/jwt",async(req,res)=>{
        const user = req.body;
        console.log("jwt...",user);
        const token = jwt.sign(user,process.env.ACCESS_TOKEN_SECRET,{
            expiresIn:'1h'
        });
        res.send({token});
    })

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

