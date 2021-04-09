// const mongoose = require('mongoose')

const mysql = require('mysql')
var express = require("express");

// mongoose.connect('mongodb://localhost:27017/NodeAuthentication').then(()=>{
//     console.log("connected")
// })

const db = mysql.createConnection({
	host: 'localhost',
	user: 'root',
	password: '',
	database: 'node_authentication',
});

db.connect(function (err) {
	if (err) {
		console.log('DB Error');
		throw err;
	} else {
		console.log('Connect');
	}
});


module.exports = db;