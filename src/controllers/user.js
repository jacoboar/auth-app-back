import { models } from 'mongoose';
import passport from 'passport';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import error_types from './error_types';

let controller = {
    /*
    Podríamos haber realizado el registro pasando por el middleware de passport, pero no es necesario,
    en este caso se realiza contra una base de datos asi que es muy sencillo hacerlo nosotros.
    */
    register: (req, res, next) => {
        console.log("caso register");
        models.User.findOne({ username: req.body.username })
            .then(data => { //si la consulta se ejecuta
                if (data) { //si el usuario existe
                    throw new error_types.InfoError("user already exists");
                }
                else { //si no existe el usuario se crea/registra
                    console.log("creando usuario");
                    var hash = bcrypt.hashSync(req.body.password, parseInt(process.env.BCRYPT_ROUNDS));
                    let document = new models.User({
                        username: req.body.username,
                        email: req.body.email || '',
                        password: hash
                    });
                    return document.save();
                }
            })
            .then(data => { //usuario registrado con exito, pasamos al siguiente manejador
                res.json({ data: data });
            })
            .catch(err => { //error en registro, lo pasamos al manejador de errores
                next(err);
            })
    },
    login: (req, res, next) => {
        console.log("caso login");
        passport.authenticate("local", { session: false }, (error, user) => {
            console.log('error', error);
            console.log('user', user);
            console.log("ejecutando *callback auth* de authenticate para estrategia local");
            //si hubo un error en el callback verify relacionado con la consulta de datos de usuario
            if (error || !user) {
                next(new error_types.Error404("username or password not correct."))
            }else {
                console.log("*** comienza generacion token ***");
                const payload = {
                    sub: user._id,
                    exp: Date.now() + parseInt(process.env.JWT_LIFETIME),
                    username: user.username
                };

                /* NOTA: Si estuviesemos usando sesiones, al usar un callback personalizado, 
                es nuestra responsabilidad crear la sesión.
                Por lo que deberiamos llamar a req.logIn(user, (error)=>{}) aquí*/

                /*solo inficamos el payload ya que el header ya lo crea la lib jsonwebtoken internamente
                para el calculo de la firma y así obtener el token*/
                const token = jwt.sign(JSON.stringify(payload), process.env.JWT_SECRET, {algorithm: process.env.JWT_ALGORITHM});
                res.json({ data: { token: token } });
            }

        })(req, res);
    }
}

module.exports = controller;