const mongoose = require("mongoose");

const mongoConnect = async ()=>{
    try{
        await mongoose.connect(process.env.DB_URL);
        console.log("DataBase connected")
    }catch(err){
        console.log("DataBase connection failed ",err.message);
        process.exit(1);
    }
}
 


module.exports = mongoConnect;