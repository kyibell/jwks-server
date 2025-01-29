import express from "express";

const app = express(); // Init app
const port = 8080; // Variable for Port


const server = app.listen(port, () => { // server start
    console.log(`App is listening and running on local host on port ${port}`); // Message if successful
});


server.on('error', (error) => { // Error handling
    console.log('Error starting server', error);
});

