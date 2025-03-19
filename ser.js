const express = require("express");
const cors = require("cors");
const path = require("path");

const app = express();


app.use(cors()); 
app.use(express.json()); 

app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
    res.send("Hello, this is the homepage!");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
