const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const UserSchema = new Schema({
    name:{
        type:String,
        require:true,
        min:6,
        max:255
    },
    username:{
        type:String,
        require:true,
        min:6,
        max:255
    },
    password:{
        type:String,
        require:true,
        min:6,
        max:1024
    }
},{timestamps:true},{collections:'user'});

const User = mongoose.model('User',UserSchema);

module.exports = User;


