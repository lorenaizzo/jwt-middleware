const express = require('express');
const jwt = require('jsonwebtoken');
const unless = require('express-unless');
const bcrypt = require('bcrypt');

const app =  express();
const port = process.env.PORT ? process.env.PORT : 3000;

app.use(express.json());

const auth = (req, res, next) => {
    try {      
        let token = req.headers['authorization']
        
        if(!token){
            throw new Error("No estas logueado");
        }

        token = token.replace('Bearer ', '')

        jwt.verify(token, 'Secret', (err, user) => {
            if (err) {
                    throw new Error("Token invalido");
            }
        });

        next();
    }
    catch(e){
        res.status(403).send({message: e.message});
    }
}

auth.unless = unless;

app.use(auth.unless({
    path: [
      { url: '/login', methods: ['POST']  },
      { url: '/registro', methods: ['POST']}
    ]
  }));



//Autenticacion
//Paso 1 Registracion
app.post('/registro', async (req, res)=>{
    try{
        if(!req.body.usuario || !req.body.clave || !req.body.email || !req.body.celu) {
            throw new Error("No enviaste todos los datos necesarios");
        }

        //Verifico que no exista el nombre de usuario
        // entonces consulto en la base de datos
        //select * from usuario where usuario = req.body.usuario
        // usuario.find({usuario: req.body.usuario})
        // si existe mando error
        
        //Si esta todo bien, encripto la clave
        const claveEncriptada = await bcrypt.hash(req.body.clave, 10);

        // Guardar el usuario con la clave encriptada
        const usuario = {
            usuario: req.body.usuario,
            clave: claveEncriptada,
            email:req.body.email,
            celu: req.body.celu
        }

        res.send({message: "Se registro correctamente"});
    }
    catch(e) {
        res.status(413).send({message: e.message});
    }
});

//Paso 2 Login
app.post('/login', (req, res)=>{
    try{
        if(!req.body.usuario || !req.body.clave) {
            throw new Error("No enviaste los datos necesarios");
        }

        // Paso 1: encuentro el usuario en la base de datos
        // select * from usuario where usuario = req.body.usuario
        // usuario.find({usuario: req.body.usuario})
        // si no lo encontras -> error
        //const claveEncriptada = "fdfadsfds";

        // Paso 2: verificar la clave
        //if(!bcrypt.compareSync(req.body.clave, claveEncriptada)){
        //    throw new Error("Fallo el login");
        //}

        // Paso 3: sesion
        const tokenData = {
            nombre: "Lorena",
            apellido: "Izzo",
            user_id: 1
        }        
        
        const token = jwt.sign(tokenData, 'Secret', {
            expiresIn: 60 * 60 * 24 // expires in 24 hours
        })  

        res.send({token});

    }
    catch(e) {
        res.status(413).send({message: e.message});
    }
});

app.get('/libros', (req, res)=>{
    try{
        res.send({message: "lista de libros"});
    }
    catch(e) {
        res.status(413).send({message: e.message});
    }
});


app.get('/genero', (req, res)=>{
    try{
        res.send({message: "lista de generos"});
    }
    catch(e) {
        res.status(413).send({message: e.message});
    }
});







app.listen(port, ()=>{
    console.log("Servidor escuchando en el puerto ", port);
})


/*
app.post('/', (req, res)=>{
    try{

    }
    catch(e) {
        res.status(413).send({message: e.message});
    }
});
*/