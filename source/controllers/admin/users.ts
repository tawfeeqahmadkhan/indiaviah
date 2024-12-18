import { NextFunction, Request, Response } from 'express';
import bcryptjs from 'bcryptjs';
import logging from "../../config/logging";
import config from "../../config/config";
import header from "../../middleware/apiHeader";
import signJWT from '../../function/signJTW';
import { ResultSuccess } from '../../classes/response/resultsuccess';
import { ResultError } from '../../classes/response/resulterror';
import jwt from 'jsonwebtoken';
import createRefreshToken from '../../function/refreshToken';
import { encode } from 'hi-base32';
import * as OTPAuth from "otpauth";

const mysql = require('mysql');
const util = require('util');
const fs = require('fs');
// const sharp = require('sharp');
var Jimp = require("jimp");
const Cryptr = require('cryptr');
const cryptr = new Cryptr('myTotallySecretKey');
const nodemailer = require("nodemailer");

// let connection = mysql.createConnection({
//     host: config.mysql.host,
//     user: config.mysql.user,
//     password: config.mysql.password,
//     database: config.mysql.database
// });

// const query = util.promisify(connection.query).bind(connection);
// const beginTransaction = util.promisify(connection.beginTransaction).bind(connection);
// const commit = util.promisify(connection.commit).bind(connection);
// const rollback = util.promisify(connection.rollback).bind(connection);

const NAMESPACE = 'Users';

const login = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Login');
        let requiredFields = ['email', 'password'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            await header.beginTransaction();
            let userId: number;
            let insertRefTokenResult;
            let sql = `SELECT u.*, ur.roleId as roleId, roles.name as roleName, img.imageUrl as image FROM users u
                LEFT JOIN userroles ur ON ur.userId = u.id
                LEFT JOIN images img ON img.id =u.imageId
                LEFT jOIN roles ON roles.id = ur.roleId
                WHERE u.email = '` + req.body.email + `' AND u.isActive = true AND u.isDisable = false AND (ur.roleId = 1 OR ur.roleId = 3)`;
            let result = await header.query(sql);
            let userResult = result;
            userId = result[0].id;
            if (result && result.length > 0) {
                await bcryptjs.compare(req.body.password, result[0].password, async (error, hashresult: any) => {
                    if (hashresult == false) {
                        return res.status(401).json({
                            message: 'Password Mismatch'
                        });
                    } else if (hashresult) {
                        let signJWTResult: any = await signJWT(result[0]);
                        if (signJWTResult && signJWTResult.token) {
                            userResult[0].token = signJWTResult.token;
                            if (userResult[0].roleId == 3) {
                                let getUserPagesSql = `SELECT p.*, up.isReadPermission, up.isAddPermission, up.isDeletePermission, up.isEditPermission FROM pages p INNER JOIN userpages up ON up.pageId = p.id WHERE up.userId = ` + userResult[0].id
                                let getUserPagesResult = await header.query(getUserPagesSql);
                                userResult[0].pagePermissions = getUserPagesResult;
                            }
                            let refreshToken = await createRefreshToken(userResult[0]);

                            let defaultCurrencySql = `SELECT * From currencies WHERE isDefault = 1`;
                            let defaultCurrency = await header.query(defaultCurrencySql);
                            userResult[0].defaultCurrency = defaultCurrency;
                            //insert refresh token
                            let insertRefreshTokenSql = `INSERT INTO userrefreshtoken(userId, refreshToken, expireAt) VALUES(?,?,?)`;
                            insertRefTokenResult = await header.query(insertRefreshTokenSql, [userResult[0].id, refreshToken.token, refreshToken.expireAt]);
                            if (insertRefTokenResult && insertRefTokenResult.affectedRows > 0) {
                                userResult[0].refreshToken = refreshToken.token;
                                await header.commit();
                                let successResult = new ResultSuccess(200, true, 'Login User', userResult, 1, "");
                                return res.status(200).send(successResult);
                            } else {
                                await header.rollback();
                                let errorResult = new ResultError(400, true, "users.signUp() Error", new Error('Error While Login'), '');

                                next(errorResult);
                                return res.status(400).send(errorResult)
                            }
                        } else {
                            return res.status(401).json({
                                message: 'Unable to Sign JWT',
                                error: signJWTResult.error
                            });
                        }
                    }
                });
            } else {
                await header.rollback();
                let errorResult = new ResultError(400, true, "users.login() Error", new Error('Error While Login'), '');
                next(errorResult);
            }
        } else {
            await header.rollback();
            let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        await header.rollback();
        let errorResult = new ResultError(500, true, 'Users.login() Exception', error, '');
        next(errorResult);
    }
};

const addUserImageFiles = async (req: any) => {
    let result;
    let imageId;
    try {
        let sql = `INSERT INTO images(createdBy, modifiedBy) VALUES (` + req.userId + `,` + req.userId + `)`;
        result = await header.query(sql);
        if (result.affectedRows > 0) {
            imageId = result.insertId;
            let dir = './content';
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir);
            }

            let dir1 = './content/user';
            if (!fs.existsSync(dir1)) {
                fs.mkdirSync(dir1);
            }

            let dir2 = './content/user/' + req.userId;
            if (!fs.existsSync(dir2)) {
                fs.mkdirSync(dir2);
            }
            const fileContentsUser = new Buffer(req.imgData, 'base64')
            let imgPath = "./content/user/" + req.userId + "/" + result.insertId + "-realImg.jpeg";

            fs.writeFileSync(imgPath, fileContentsUser, (err: any) => {
                if (err)
                    return console.error(err)
                console.log('file saved imagePath')
            });
            let imagePath = "./content/user/" + req.userId + "/" + result.insertId + ".jpeg";
            // sharp(imgPath).resize({
            //     height: 100,
            //     width: 100
            // }).toFile(imagePath)
            //     .then(function (newFileInfo: any) {
            //         console.log(newFileInfo);
            //     });

            await Jimp.read(imgPath)
                .then((lenna: any) => {
                    return lenna
                        .resize(100, 100) // resize
                        // .quality(60) // set JPEG quality
                        // .greyscale() // set greyscale
                        // .write("lena-small-bw.jpg"); // save
                        .write(imagePath);
                })
                .catch((err: any) => {
                    console.error(err);
                });
            let updateimagePathSql = `UPDATE images SET imageUrl='` + imagePath.substring(2) + `' WHERE id=` + result.insertId;
            let updateimagePathResult = await header.query(updateimagePathSql);
            result = JSON.parse(JSON.stringify(result));
        } else {
            result = JSON.parse(JSON.stringify(result));
        }
    } catch (err) {
        let imagePath = "./content/user/" + req.userId + "/" + imageId + ".jpeg";
        if (fs.existsSync(imagePath)) {
            fs.unlink(imagePath, (err: any) => {
                if (err) throw err;
                console.log(imagePath + ' was deleted');
            });
        }
        let dir = './content/user/' + req.userId;
        if (fs.existsSync(dir)) {
            fs.rmdir(dir, (err: any) => {
                if (err) throw err;
                console.log(dir + ' was deleted');
            });
        }
        result = err;
    }
    return result;
};

const insertUser = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'SignUp');
        let requiredFields = ['firstName', 'lastName', 'email', 'password', 'contactNo', 'gender'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let result;
                req.body.middleName = req.body.middleName ? req.body.middleName : '';
                await header.beginTransaction();
                bcryptjs.hash(req.body.password, 10, async (hashError, hash) => {
                    if (hashError) {
                        return res.status(401).json({
                            message: hashError.message,
                            error: hashError
                        });
                    }
                    let checkEmailSql = `SELECT * FROM users WHERE email = '` + req.body.email + `'`;
                    let checkEmailResult = await header.query(checkEmailSql);
                    if (checkEmailResult && checkEmailResult.length > 0) {
                        await header.rollback();
                        let errorResult = new ResultError(400, true, "Email Already Inserted", new Error('Email Already Inserted'), '');
                        next(errorResult);
                        // let successResult = new ResultSuccess(200, true, 'Email Already Inserted', [], 1, "");
                        // return res.status(200).send(successResult);
                    } else {
                        let sql = `INSERT INTO users(firstName, middlename, lastName, contactNo, email, gender, password, isDisable, isReceiveMail, isReceiveNotification) 
                        VALUES('` + req.body.firstName + `','` + req.body.middleName + `','` + req.body.lastName + `',` + req.body.contactNo + `,'` + req.body.email + `','` + req.body.gender + `'
                        ,'` + hash + `',0,` + (req.body.isReceiveMail ? true : false) + `,` + (req.body.isReceiveNotification ? true : false) + `)`;
                        result = await header.query(sql);
                        if (result && result.insertId > 0) {
                            let userId = result.insertId;
                            if (req.body.image && req.body.image.indexOf('content') == -1) {
                                if (req.body.image) {
                                    let image = req.body.image;
                                    let data = image.split(',');
                                    if (data && data.length > 1) {
                                        image = image.split(',')[1]
                                    }
                                    let imageData = {
                                        imgPath: '',
                                        imgData: image,
                                        description: image,
                                        alt: image.alt,
                                        userId: userId
                                    }
                                    let imageResult = await addUserImageFiles(imageData);
                                    req.body.imageId = imageResult.insertId;
                                    if (req.body.imageId) {
                                        let sql1 = "UPDATE users SET imageId = " + req.body.imageId + " WHERE id =" + userId + "";
                                        result = await header.query(sql1);
                                    }
                                } else {
                                    req.body.imageId = null;
                                }
                            }
                            let userRoleSql = `INSERT INTO userroles(userId, roleId) VALUES (` + userId + `, 3) `;
                            result = await header.query(userRoleSql);
                            if (result && result.affectedRows > 0) {
                                // await login(req.body, res, next);
                                await header.commit();
                                let successResult = new ResultSuccess(200, true, 'Insert User', result, 1, "");
                                return res.status(200).send(successResult);
                            } else {
                                await header.rollback();
                                let errorResult = new ResultError(400, true, "users.insertUser() Error", new Error('Error While Inserting Data'), '');
                                next(errorResult);
                            }
                        } else {
                            await header.rollback();
                            let errorResult = new ResultError(400, true, "users.insertUser() Error", new Error('Error While Inserting Data'), '');
                            next(errorResult);
                        }
                    }
                });
            } else {
                let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
                next(errorResult);
            }
        } else {
            await header.rollback();
            let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        await header.rollback();
        let errorResult = new ResultError(500, true, 'users.insertUser() Exception', error, '');
        next(errorResult);
    }
};

const getAllUsers = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting All Users');
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) {
            let currentUser = authorizationResult.currentUser;
            let userId = currentUser.id;
            let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
            let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
            let countSql = `SELECT COUNT(*) as totalCount  FROM users
            LEFT JOIN userroles ur ON ur.userId = users.id
            WHERE users.isDelete = 0 AND (ur.roleId = 1 OR ur.roleId = 3) AND users.id != ` + userId;
            if (req.body.searchString) {
                if (!countSql.includes(` WHERE `)) {
                    countSql += ` WHERE `;
                } else {
                    countSql += ` AND `;
                }
                countSql += ` (users.firstName LIKE '%` + req.body.searchString + `%' OR users.lastName LIKE '%` + req.body.searchString + `%' OR users.email LIKE '%` + req.body.searchString + `%' OR users.contactNo LIKE '%` + req.body.searchString + `%' OR users.gender LIKE '%` + req.body.searchString + `%')`;
            }
            let countResult = await header.query(countSql);
            let sql = `SELECT users.*, img.imageUrl as image, ur.roleId as roleId FROM users
            LEFT JOIN images img ON img.id = users.imageId
            LEFT JOIN userroles ur ON ur.userId = users.id
            WHERE users.isDelete = 0 AND (ur.roleId = 1 OR ur.roleId = 3)  AND users.id != ` + userId;
            if (req.body.searchString) {
                if (!sql.includes(` WHERE `)) {
                    sql += ` WHERE `;
                } else {
                    sql += ` AND `;
                }
                sql += ` (users.firstName LIKE '%` + req.body.searchString + `%' OR users.lastName LIKE '%` + req.body.searchString + `%' OR users.email LIKE '%` + req.body.searchString + `%' OR users.contactNo LIKE '%` + req.body.searchString + `%' OR users.gender LIKE '%` + req.body.searchString + `%')`;
            }
            sql += " ORDER BY users.id DESC";
            if (startIndex != null && fetchRecord != null) {
                sql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
            }
           
            let result = await header.query(sql);
            if (result && result.length > 0) {
                let successResult = new ResultSuccess(200, true, 'Get Users Successfully', result, countResult[0].totalCount, authorizationResult.token);
                console.log(successResult);
                return res.status(200).send(successResult);
            } else {
                let errorResult = new ResultError(400, true, 'Data Not Available', new Error('Data Not Available'), '');
                next(errorResult);
            }
        } else {
            let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'users.getAllUsers() Exception', error, '');
        next(errorResult);
    }
};

const getUserDetailById = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting User Detail');
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) {
            let currentUser = authorizationResult.currentUser;
            let userId = currentUser.id;
            let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
            let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
            let sql = `SELECT users.*, img.imageUrl as image, ur.roleId as roleId, , roles.name as roleName FROM users
            LEFT JOIN images img ON img.id = users.imageId
            LEFT JOIN userroles ur ON ur.userId = users.id
            LEFT jOIN roles ON roles.id = ur.roleId
        WHERE users.isDelete = 0 AND (ur.roleId = 1 OR ur.roleId = 3)  AND users.id = ` + userId;
            let result = await header.query(sql);
            if (result && result.length > 0) {
                let successResult = new ResultSuccess(200, true, 'Get User Detail Successfully', result, result.totalCount, authorizationResult.token);
                console.log(successResult);
                return res.status(200).send(successResult);
            } else {
                let errorResult = new ResultError(400, true, 'Data Not Available', new Error('Data Not Available'), '');
                next(errorResult);
            }
        } else {
            let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'users.getUserDetailById() Exception', error, '');
        next(errorResult);
    }
};

const updateUser = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Updating Users');
        let requiredFields = ['id', 'firstName', 'lastName', 'email', 'contactNo', 'gender'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                await header.beginTransaction();
                req.body.firstName = req.body.firstName ? req.body.firstName : '';
                req.body.middleName = req.body.middleName ? req.body.middleName : '';
                req.body.lastName = req.body.lastName ? req.body.lastName : '';
                req.body.contactNo = req.body.contactNo ? req.body.contactNo : '';
                req.body.email = req.body.email ? req.body.email : '';
                req.body.gender = req.body.gender ? req.body.gender : '';
                let oldImageId
                let userId = req.body.id;
                let checkEmailSql = `SELECT * FROM users WHERE email = '` + req.body.email + `' AND id != ` + req.body.id + ` AND isDelete = 0`;
                let checkEmailResult = await header.query(checkEmailSql);
                if (checkEmailResult && checkEmailResult.length > 0) {
                    await header.rollback();
                    let errorResult = new ResultError(400, true, "users.insertUser() Error", new Error('Email Already Inserted'), '');
                    next(errorResult);
                } else {
                    let getImageIdSql = `select users.id, users.imageId from users where id = ` + req.body.id + ``;
                    let usersResult = await header.query(getImageIdSql);
                    if (usersResult && usersResult.length > 0) {
                        oldImageId = usersResult[0].imageId;
                    }
                    if (req.body.image && req.body.image.indexOf('content') == -1) {
                        if (req.body.image) {
                            let image = req.body.image;
                            let data = image.split(',');
                            if (data && data.length > 1) {
                                image = image.split(',')[1]
                            }
                            let imageData = {
                                imgPath: '',
                                imgData: image,
                                description: image,
                                alt: image.alt,
                                userId: userId
                            }
                            let imageResult = await addUserImageFiles(imageData);
                            if (imageResult && imageResult.insertId > 0) {
                                req.body.imageId = imageResult.insertId;
                            } else {
                                await header.rollback();
                                return imageResult;
                            }
                        } else if (req.body.image == undefined || req.body.image == '') {
                            req.body.imageId = null;
                        }
                    } else if (!req.body.image || req.body.image == undefined) {
                        req.body.imageId = null;
                        let imageSql = `SELECT * FROM images WHERE id = ` + oldImageId;
                        let imageResult = await header.query(imageSql);
                        if (imageResult && imageResult.length > 0) {
                            if (imageResult[0].imageUrl) {
                                let imagePath = "./" + imageResult[0].imageUrl;
                                if (fs.existsSync(imagePath)) {
                                    fs.unlink(imagePath, (err: any) => {
                                        if (err) throw err;
                                        console.log(imagePath + ' was deleted');
                                    });
                                }
                                //Delete URL
                            }
                        }
                    } else if (req.body.image) {
                        req.body.imageId = oldImageId;
                    }

                    let sql = `UPDATE users SET firstName = '` + req.body.firstName + `', middleName = '` + req.body.middleName + `',lastName = '` + req.body.lastName + `'
                    ,contactNo = '` + req.body.contactNo + `',email = '` + req.body.email + `',gender = '` + req.body.gender + `',imageId = ` + req.body.imageId + ` 
                    ,isReceiveMail = `+ (req.body.isReceiveMail ? true : false) + `, isReceiveNotification =` + (req.body.isReceiveNotification ? true : false) + `
                    WHERE id = ` + req.body.id + ``;
                    // isPasswordSet = '` + req.body.isPasswordSet + `',isDisabled = '` + req.body.isDisabled + `',isVerified = '` + req.body.isVerified + `',imageId = ` + req.body.imageId + `
                    let result = await header.query(sql);
                    if (result && result.affectedRows > 0) {
                        if (req.body.imageId && req.body.imageId != oldImageId) {
                            let delSql = `DELETE FROM images where Id = ` + oldImageId;
                            let delResult = await header.query(delSql);

                            if (delResult && delResult.affectedRows > 0) {
                                if (fs.existsSync("./content/user/" + req.body.id + "/" + oldImageId + ".jpeg")) {
                                    fs.unlink("./content/user/" + req.body.id + "/" + oldImageId + ".jpeg", (err: any) => {
                                        if (err) throw err;
                                        console.log('Image was deleted');
                                    });
                                }
                                if (fs.existsSync("./content/user/" + req.body.id + "/" + oldImageId + "-realImg.jpeg")) {
                                    fs.unlink("./content/user/" + req.body.id + "/" + oldImageId + "-realImg.jpeg", (err: any) => {
                                        if (err) throw err;
                                        console.log('Image was deleted');
                                    });
                                }
                                let userSql = `SELECT u.*, img.imageUrl FROM users u
                            LEFT JOIN images img ON img.id = u.imageId
                            WHERE u.id = ` + req.body.id;
                                let userResult = await header.query(userSql);
                                if (userResult && userResult.length > 0) {
                                    let successResult = new ResultSuccess(200, true, 'Update User Profile Pic', userResult, userResult.length, authorizationResult.token);
                                    return res.status(200).send(successResult);
                                } else {
                                    let errorResult = new ResultError(400, true, "users.updateUserProfilePic() Error", new Error('Error While Updating Profile Pic'), '');
                                    next(errorResult);
                                }
                            }
                        }
                        await header.commit();
                        let successResult = new ResultSuccess(200, true, 'Update User Detail', result, 1, authorizationResult.token);
                        return res.status(200).send(successResult);
                    } else {
                        await header.rollback();
                        let errorResult = new ResultError(203, true, "users.updateUSers() Error", new Error('Error While Updating Data'), '');
                        next(errorResult);
                    }
                }
            } else {
                await header.rollback();
                let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
                next(errorResult);
            }
        } else {
            await header.rollback();
            let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        await header.rollback();
        let errorResult = new ResultError(500, true, 'users.updateUSers() Exception', error, '');
        next(errorResult);
    }
};

const validateToken = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Checking Token');
        let statusCode = 200;
        let message = '';

        if (req.body.token) {
            await jwt.verify(req.body.token, config.server.token.secret, async (error: any, decoded: any) => {
                if (error) {
                    statusCode = 400;
                    message = "UnAuthorize";
                } else {
                    let decodeVal = decoded;
                    if ((new Date().getTime() / 1000) <= decodeVal.exp) {
                        // console.log("Valid Live Token");
                        return true;
                    } else {
                        // console.log("Valid Expire Token");
                        return false;
                    }
                }
            });
        } else {
            // console.log('error');
            let err = 'error'
            return err;
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'users.updateUSers() Exception', error, '');
        next(errorResult);
    }
};

const activeInactiveUsers = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Active Inactive Users');
        let requiredFields = ['id'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let sql = `UPDATE users set isActive = !isActive WHERE id = ` + req.body.id + ``;
                let result = await header.query(sql);
                let successResult = new ResultSuccess(200, true, 'Change User Status', result, 1, authorizationResult.token);
                return res.status(200).send(successResult);
            }
            else {
                let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
                next(errorResult);
            }
        } else {
            let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'users.activeInactiveUsers() Exception', error, '');
        next(errorResult);
    }
};

const resetPassword = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Reset Password');
        let requiredFields = ['id', 'password', 'token'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            bcryptjs.hash(req.body.password, 10, async (hashError, hash) => {
                if (hashError) {
                    return res.status(401).json({
                        message: hashError.message,
                        error: hashError
                    });
                }
                let sql = `UPDATE users SET password = '` + hash + `' where id = ` + req.body.id + ``;
                let result = await header.query(sql);
                if (result && result.affectedRows > 0) {
                    if (req.body.token) {
                        let userTokenUpdateSql = `UPDATE usertokens SET isUsed = 1 WHERE token = '` + req.body.token + `' AND userId = ` + req.body.id + ``;
                        result = await header.query(userTokenUpdateSql);
                    }
                    let successResult = new ResultSuccess(200, true, 'Password reset successfully!', result, 1, "null");
                    return res.status(200).send(successResult);
                }
                else {
                    await header.rollback();
                    let errorResult = new ResultError(400, true, "users.resetPassword() Error", new Error('Error While Reset Password'), '');
                    next(errorResult);
                }
            });
        } else {
            await header.rollback();
            let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        await header.rollback();
        let errorResult = new ResultError(500, true, 'users.resetPassword() Exception', error, '');
        next(errorResult);
    }
};

const forgotPassword = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Reset Password');
        let requiredFields = ['email'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            await header.beginTransaction();
            let result: any;
            let sql = `SELECT * FROM users WHERE email = '` + req.body.email + `'`;
            let userData = await header.query(sql);
            if (userData && userData.length > 0) {
                let token = cryptr.encrypt(makeid(10));//crypto.randomBytes(48).toString('hex');
                let expireAtDate = new Date(new Date().toUTCString());
                expireAtDate.setDate(expireAtDate.getDate() + 1);
                let data = {
                    userId: userData[0].id,
                    token: token,
                    isUsed: 0,
                    expireAt: expireAtDate,
                    isActive: true,
                    isDelete: false,
                    createdDate: new Date(new Date().toUTCString()),
                    modifiedDate: new Date(new Date().toUTCString())
                }
                let sql = "INSERT INTO usertokens SET ?";
                result = await header.query(sql, data);
                if (result.insertId > 0) {
                    let resultEmail = await sendEmail(config.emailMatrimonySetPassword.fromName + ' <' + config.emailMatrimonySetPassword.fromEmail + '>', userData[0].email, config.emailMatrimonySetPassword.subject, "", config.emailMatrimonySetPassword.html.replace("[VERIFICATION_TOKEN]", token).replace("[NAME]", userData[0].firstName + ' ' + userData[0].lastName), null, null);
                    await header.commit();
                    result = resultEmail;
                    let successResult = new ResultSuccess(200, true, 'Send mail successfully!', result, 1, "");
                    return res.status(200).send(successResult);
                } else {
                    await header.rollback();
                    result.length = 0;
                }
            } else {
                await header.rollback();
                let errorResult = new ResultError(400, true, 'User not found', new Error('Data Not Available'), '');
                next(errorResult);
            }
        } else {
            await header.rollback();
            let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        await header.rollback();
        let errorResult = new ResultError(500, true, 'users.resetPassword() Exception', error, '');
        next(errorResult);
    }
};

const sendEmail = async (from: string, to: string, subject: string, text: string, html: any, fileName: any, invoicePdf: any) => {
    let result;
    try {
        // create reusable transporter object using the default SMTP transport
        let systemFlags = `SELECT * FROM systemflags where flagGroupId = 2`;
        let _systemFlags = await header.query(systemFlags);
        let _host;
        let _port;
        let _secure;
        let _user;
        let _password;

        for (let i = 0; i < _systemFlags.length; i++) {
            if (_systemFlags[i].id == 4) {
                _host = _systemFlags[i].value;
            } else if (_systemFlags[i].id == 5) {
                _port = parseInt(_systemFlags[i].value);
            } else if (_systemFlags[i].id == 6) {
                if (_systemFlags[i].value == '1') {
                    _secure = true;
                } else {
                    _secure = false;
                }
            } else if (_systemFlags[i].id == 1) {
                _user = _systemFlags[i].value;
            } else if (_systemFlags[i].id == 2) {
                _password = _systemFlags[i].value;
            }
        }
        // create reusable transporter object using the default SMTP transport
        let transporter = nodemailer.createTransport({
            host: _host,
            port: _port,
            secure: _secure, // true for 465, false for other ports
            auth: {
                user: _user,
                pass: _password
            }
        });
        // setup email data with unicode symbols
        let mailOptions = {
            from: _user,
            to: to,
            subject: subject,
            html: html
        };

        // send mail with defined transport object
        result = await transporter.sendMail(mailOptions);

        // console.log("Message sent: %s", result);
    } catch (error) {
        result = error;
    }
    return result;
};

const verifyforgotPasswordLink = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Verify Forgot Password Link');
        let requiredFields = ['token'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let result;
            let sql = `SELECT * FROM usertokens WHERE isDelete = 0 AND isUsed = 0  AND token = '` + req.body.token + `'`;
            result = await header.query(sql);
            if (result && result.length > 0) {
                let expireDate = new Date(result[0].expireAt);
                let currentDate = new Date(new Date().toUTCString());
                let exTime = expireDate.getTime();
                let curTime = currentDate.getTime();
                if (exTime > curTime) {
                    let successResult = new ResultSuccess(200, true, 'Token is valid!', result, 1, "null");
                    return res.status(200).send(successResult);
                } else {
                    let successResult = 'Token is expired!'
                    return res.status(200).send(successResult);
                }
            } else {
                let successResult = 'You have already used this token';
                return res.status(200).send(successResult);
            }
        } else {
            await header.rollback();
            let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'users.verifyforgotPasswordLink() Exception', error, '');
        next(errorResult);
    }
};

const blockUser = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Block User');
        let requiredFields = ['id'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let sql = `UPDATE users set isDisable = !isDisable WHERE id = ` + req.body.id + ``;
                let result = await header.query(sql);
                if (result && result.affectedRows > 0) {
                    let successResult = new ResultSuccess(200, true, 'User Block Sucessfully', result, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "users.blockUser() Error", new Error('Error While Block User'), '');
                    next(errorResult);
                }
            } else {
                let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
                next(errorResult);
            }
        } else {
            await header.rollback();
            let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'users.blockUser() Exception', error, '');
        next(errorResult);
    }
};

const deleteUser = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Delete User');
        let requiredFields = ['id'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let sql = `DELETE FROM users WHERE id = ` + req.body.id + ``;
                let result = await header.query(sql);
                if (result && result.affectedRows > 0) {
                    let successResult = new ResultSuccess(200, true, 'Delete User Sucessfully', result, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "users.deleteUser() Error", new Error('Error While Deleting Users'), '');
                    next(errorResult);
                }
            } else {
                let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
                next(errorResult);
            }
        } else {
            await header.rollback();
            let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'users.deleteUser() Exception', error, '');
        next(errorResult);
    }
};

const updateFCMToken = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'updateFCMToken');
        let requiredFields = ['fcmToken'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let userId = authorizationResult.currentUser.id;

                let userDevice = authorizationResult.currentUserDevice;
                let appId: number;
                if (userDevice.app == 'MatrimonyAdmin') {
                    appId = 1;
                } else if (userDevice.app == 'MatrimonyAndroid') {
                    appId = 2;
                } else {
                    appId = 3;
                }

                let getUserDeviceDetailSql = `SELECT * FROM userdevicedetail WHERE userId = ` + userId;
                let getUserDeviceDetailResult = await header.query(getUserDeviceDetailSql);
                if (getUserDeviceDetailResult && getUserDeviceDetailResult.length > 0) {
                    let updateSql = `UPDATE userdevicedetail SET fcmToken = '` + req.body.fcmToken + `', applicationId = ` + appId + ` WHERE id = ` + getUserDeviceDetailResult[0].id;
                    let updateResult = await header.query(updateSql);
                    if (updateResult && updateResult.affectedRows >= 0) {
                        let successResult = new ResultSuccess(200, true, 'Update User Detail', updateResult, 1, authorizationResult.token);
                        return res.status(200).send(successResult);
                    } else {
                        let errorResult = new ResultError(400, true, "users.updateFCMToken() Error", new Error('Error While Updating FCM Token'), '');
                        next(errorResult);
                    }
                } else {
                    let insertSql = `INSERT INTO userdevicedetail(userId, applicationId, fcmToken, isActive, isDelete, createdBy, modifiedBy) 
                    VALUES(` + userId + `,` + appId + `,'` + req.body.fcmToken + `',1,0,` + userId + `,` + userId + `)`;
                    let insertResult = await header.query(insertSql);
                    if (insertResult && insertResult.insertId >= 0) {
                        let successResult = new ResultSuccess(200, true, 'Update User Detail', insertResult, 1, authorizationResult.token);
                        return res.status(200).send(successResult);
                    } else {
                        let errorResult = new ResultError(400, true, "users.updateFCMToken() Error", new Error('Error While Updating FCM Token'), '');
                        next(errorResult);
                    }
                }
            } else {
                let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
                next(errorResult);
            }
        } else {
            await header.rollback();
            let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        await header.rollback();
        let errorResult = new ResultError(500, true, 'users.updateFCMToken() Exception', error, '');
        next(errorResult);
    }
};

const updateEmail = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Update Email');
        let requiredFields = ['email'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let userId = authorizationResult.currentUser.id;
                let sql = "SELECT * FROM users WHERE id = " + userId;
                let result = await header.query(sql);
                if (result && result.length > 0) {
                    let updateSql = `UPDATE users SET email = '` + req.body.email + `' WHERE id = ` + userId;
                    result = await header.query(updateSql);
                    if (result && result.affectedRows > 0) {
                        let successResult = new ResultSuccess(200, true, 'User Email Update Successfully', result, 1, authorizationResult.token);
                        return res.status(200).send(successResult);
                    } else {
                        let errorResult = new ResultError(400, true, "users.updateEmail() Error", new Error('Error While Update Email'), '');
                        next(errorResult);
                    }
                } else {
                    let errorResult = new ResultError(400, true, "users.updateEmail() Error", new Error('Error While Update Email'), '');
                    next(errorResult);
                }
            } else {
                let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
                next(errorResult);
            }
        } else {
            await header.rollback();
            let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        await header.rollback();
        let errorResult = new ResultError(500, true, 'users.updateEmail() Exception', error, '');
        next(errorResult);
    }
}

const updatePassword = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Update Password');
        let requiredFields = ['password'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let userId = authorizationResult.currentUser.id;
                let sql = "SELECT * FROM users WHERE id = " + userId;
                let result = await header.query(sql);
                if (result && result.length > 0) {
                    bcryptjs.hash(req.body.password, 10, async (hashError, hash) => {
                        if (hashError) {
                            return res.status(401).json({
                                message: hashError.message,
                                error: hashError
                            });
                        }
                        let updateSql = `UPDATE users SET password = '` + hash + `' WHERE id = ` + userId;
                        result = await header.query(updateSql);
                        if (result && result.affectedRows > 0) {
                            let successResult = new ResultSuccess(200, true, 'User Password Update Successfully', result, 1, authorizationResult.token);
                            return res.status(200).send(successResult);
                        } else {
                            let errorResult = new ResultError(400, true, "users.updatePassword() Error", new Error('Error While Update Email'), '');
                            next(errorResult);
                        }
                    });
                } else {
                    let errorResult = new ResultError(400, true, "users.updatePassword() Error", new Error('Error While Update Email'), '');
                    next(errorResult);
                }
            } else {
                let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
                next(errorResult);
            }
        } else {
            await header.rollback();
            let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        await header.rollback();
        let errorResult = new ResultError(500, true, 'users.updatePassword() Exception', error, '');
        next(errorResult);
    }
}

// const sendAuthenticationCodeToEmail = async (req: Request, res: Response, next: NextFunction) => {
//     try {
//         logging.info(NAMESPACE, 'Update Password');
//         let requiredFields = [''];
//         let validationResult = header.validateRequiredFields(req, requiredFields);
//         if (validationResult && validationResult.statusCode == 200) {
//             let authorizationResult = await header.validateAuthorization(req, res, next);
//             if (authorizationResult.statusCode == 200) {
//                 let userId = authorizationResult.currentUser.id;
//                 let code = Math.floor(100000 + Math.random() * 900000);
//                 req.body.isTwoFactorEnable = req.body.isTwoFactorEnable ? req.body.isTwoFactorEnable : (req.body.isTwoFactorEnable == false ? false : null);
//                 let sql = `UPDATE users SET twoFactorCode = '` + code + `', isTwoFactorEnable = ` + req.body.isTwoFactorEnable + ` WHERE id = ` + userId;
//                 let result = await header.query(sql);
//                 if (result && result.affectedRows >= 0) {
//                     let sqlData = `SELECT * FROM users WHERE id = ` + userId;
//                     let resultData = await header.query(sqlData);

//                     let resultEmail = await sendEmail(config.emailMatrimonyTwoFactorAuthentication.fromName + ' <' + config.emailMatrimonyTwoFactorAuthentication.fromEmail + '>'
//                         , resultData[0].email
//                         , config.emailMatrimonyTwoFactorAuthentication.subject
//                         , ""
//                         , config.emailMatrimonyTwoFactorAuthentication.html
//                             .replace("[FullName]", resultData[0].firstName + " " + resultData[0].lastName)
//                             .replace("[VerificationCode]", code.toString())
//                         , null, null);

//                     let successResult = new ResultSuccess(200, true, 'Send Authentication Code Successfully', result, 1, authorizationResult.token);
//                     return res.status(200).send(successResult);
//                 } else {
//                     let errorResult = new ResultError(400, true, "users.sendAuthenticationCodeToEmail() Error", new Error('Error While Sending Email'), '');
//                     next(errorResult);
//                 }
//             } else {
//                 let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
//                 next(errorResult);
//             }
//         } else {
//             await header.rollback();
//             let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
//             next(errorResult);
//         }
//     } catch (error: any) {
//         await header.rollback();
//         let errorResult = new ResultError(500, true, 'users.sendAuthenticationCodeToEmail() Exception', error, '');
//         next(errorResult);
//     }
// }

// const verifyAuthenticationCode = async (req: Request, res: Response, next: NextFunction) => {
//     try {
//         logging.info(NAMESPACE, 'Verify Authentication Code');
//         let requiredFields = ['twoFactorCode'];
//         let validationResult = header.validateRequiredFields(req, requiredFields);
//         if (validationResult && validationResult.statusCode == 200) {
//             let authorizationResult = await header.validateAuthorization(req, res, next);
//             if (authorizationResult.statusCode == 200) {
//                 let userId = authorizationResult.currentUser.id;
//                 let sql = `SELECT * FROM users WHERE twoFactorCode = '` + req.body.twoFactorCode + `'`;
//                 let result = await header.query(sql);
//                 if (result && result.length > 0) {
//                     let successResult = new ResultSuccess(200, true, 'Verify Authentication Code successfully', result, 1, authorizationResult.token);
//                     return res.status(200).send(successResult);
//                 } else {
//                     let errorResult = new ResultError(400, true, "users.verifyAuthenticationCode() Error", new Error('Error While update status'), '');
//                     next(errorResult);
//                 }
//             } else {
//                 let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
//                 next(errorResult);
//             }
//         } else {
//             await header.rollback();
//             let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
//             next(errorResult);
//         }
//     } catch (error: any) {
//         await header.rollback();
//         let errorResult = new ResultError(500, true, 'users.verifyAuthenticationCode() Exception', error, '');
//         next(errorResult);
//     }
// }

const updateAuthenticationStatus = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Update Password');
        let requiredFields = [''];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let userId = authorizationResult.currentUser.id;
                let checkSql = `SELECT * FROM users WHERE id = ` + userId;
                let checkResult = await header.query(checkSql);
                let flag = true;
                if (checkResult && checkResult.length > 0) {
                    if (checkResult[0].otpAuthUrl && checkResult[0].baseSecret) {
                        flag = false;
                    }
                }
                if (flag && req.body.isTwoFactorEnable) {
                    let sysFalgSql = `SELECT * FROM systemflags WHERE flagGroupId = 10`;
                    let sysFalgResult = await header.query(sysFalgSql);
                    let issuer = "";
                    let label = "";
                    if (sysFalgResult && sysFalgResult.length > 0) {
                        issuer = sysFalgResult[sysFalgResult.findIndex((c: any) => c.name == 'twoFactorIssuer')].value;
                        label = sysFalgResult[sysFalgResult.findIndex((c: any) => c.name == 'twoFactorLabel')].value;
                    }
                    const base32_secret = generateRandomBase32();
                    let totp = new OTPAuth.TOTP({
                        issuer: issuer,//"native.software",
                        label: label,//''"nativesoftware",
                        algorithm: "SHA1",
                        digits: 6,
                        secret: base32_secret,
                    });
                    let otpauth_url = totp.toString();
                    let sql = `UPDATE users SET otpAuthUrl = '` + otpauth_url + `', baseSecret='` + base32_secret + `', isTwoFactorEnable = true  WHERE id = ` + userId;
                    let result = await header.query(sql);
                    if (result && result.affectedRows >= 0) {
                        let getSql = "SELECT * FROM users WHERE  id =" + userId;
                        let getResult = await header.query(getSql);
                        let successResult = new ResultSuccess(200, true, 'Generate OTP Successfully', getResult, 1, authorizationResult.token);
                        return res.status(200).send(successResult);
                    } else {
                        let errorResult = new ResultError(400, true, "users.generateOTP() Error", new Error('Error While update status'), '');
                        next(errorResult);
                    }
                } else {
                    req.body.isTwoFactorEnable = req.body.isTwoFactorEnable ? req.body.isTwoFactorEnable : (req.body.isTwoFactorEnable == false ? false : null);
                    let sql = `UPDATE users SET isTwoFactorEnable = ` + req.body.isTwoFactorEnable + ` WHERE id = ` + userId;
                    let result = await header.query(sql);
                    if (result && result.affectedRows >= 0) {
                        let getUserSql = `SELECT * FROM users where id = ` + userId;
                        let getUserResult = await header.query(getUserSql);
                        let successResult = new ResultSuccess(200, true, 'Send Authentication Code Successfully', getUserResult, 1, authorizationResult.token);
                        return res.status(200).send(successResult);
                    } else {
                        let errorResult = new ResultError(400, true, "users.updateAuthenticationStatus() Error", new Error('Error While update status'), '');
                        next(errorResult);
                    }
                }
            } else {
                let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
                next(errorResult);
            }
        } else {
            await header.rollback();
            let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        await header.rollback();
        let errorResult = new ResultError(500, true, 'users.updateAuthenticationStatus() Exception', error, '');
        next(errorResult);
    }
}

const changeEmail = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Reset Password');
        let requiredFields = ['oldEmail', 'newEmail'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let currentUser = authorizationResult.currentUser;
                let userId = currentUser.id;
                let result;
                let searchSql = `SELECT * FROM users WHERE email = '` + req.body.oldEmail + `' AND id = ` + userId;
                let searchResult = await header.query(searchSql);
                if (searchResult && searchResult.length > 0) {
                    let checkSql = `SELECT * FROM users WHERE email = '` + req.body.newEmail + `' AND id != ` + userId + ``;
                    result = await header.query(checkSql);
                    if (result && result.length > 0) {
                        let errorResult = new ResultError(203, true, "users.changeEmail() Error", new Error('Email Already exists'), '');
                        next(errorResult);
                    } else {
                        let sql = `UPDATE users SET email = '` + req.body.newEmail + `' where id = ` + userId + ``;
                        result = await header.query(sql);
                        if (result && result.affectedRows > 0) {
                            let successResult = new ResultSuccess(200, true, 'Email Change successfully!', result, 1, "null");
                            return res.status(200).send(successResult);
                        } else {
                            await header.rollback();
                            let errorResult = new ResultError(400, true, "users.changeEmail() Error", new Error('Error While Change Password'), '');
                            next(errorResult);
                        }
                    }
                } else {
                    let errorResult = "User Not Found";
                    next(errorResult);
                }
            } else {
                let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
                next(errorResult);
            }
        } else {
            await header.rollback();
            let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        await header.rollback();
        let errorResult = new ResultError(500, true, 'users.changeEmail() Exception', error, '');
        next(errorResult);
    }
};

const changePassword = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Change Password');
        let requiredFields = ['oldPassword', 'newPassword'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let currentUser = authorizationResult.currentUser;
                let userId = currentUser.id;
                let result;
                let sql = `SELECT * FROM users WHERE id = ` + userId;
                result = await header.query(sql);
                if (result && result.length > 0) {
                    bcryptjs.compare(req.body.oldPassword, result[0].password, async (error, hashresult: any) => {
                        if (hashresult == false) {
                            return res.status(203).json({
                                message: 'Your old password is not match'
                            });
                        } else if (hashresult) {
                            bcryptjs.hash(req.body.newPassword, 10, async (hashError, hash) => {
                                if (hashError) {
                                    return res.status(401).json({
                                        message: hashError.message,
                                        error: hashError
                                    });
                                }
                                let sql = `UPDATE users SET password = '` + hash + `' where id = ` + userId + ``;
                                let result = await header.query(sql);
                                if (result && result.affectedRows > 0) {
                                    let successResult = new ResultSuccess(200, true, 'Password Change successfully!', result, 1, "null");
                                    return res.status(200).send(successResult);
                                } else {
                                    await header.rollback();
                                    let errorResult = new ResultError(400, true, "users.changePassword() Error", new Error('Error While Change Password'), '');
                                    next(errorResult);
                                }
                            });
                        }
                    });
                } else {
                    let errorResult = "User Not Found";
                    next(errorResult);
                }
            } else {
                let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
                next(errorResult);
            }
        } else {
            await header.rollback();
            let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        await header.rollback();
        let errorResult = new ResultError(500, true, 'users.changePassword() Exception', error, '');
        next(errorResult);
    }
};

function makeid(length: number) {
    let result = '';
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const charactersLength = characters.length;
    let counter = 0;
    while (counter < length) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
        counter += 1;
    }
    return result;
}

const generateRandomBase32 = () => {
    const buffer = cryptr.encrypt(makeid(10));
    const base32 = encode(buffer).replace(/=/g, "").substring(0, 24);
    return base32;
};

const generateOTP = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Generate OTP');
        let requiredFields = [''];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let userId = authorizationResult.currentUser.id;
                const base32_secret = generateRandomBase32();
                let sysFalgSql = `SELECT * FROM systemflags WHERE flagGroupId = 10`;
                let sysFalgResult = await header.query(sysFalgSql);
                let issuer = "";
                let label = "";
                if (sysFalgResult && sysFalgResult.length > 0) {
                    issuer = sysFalgResult[sysFalgResult.findIndex((c: any) => c.name == 'twoFactorIssuer')].value;
                    label = sysFalgResult[sysFalgResult.findIndex((c: any) => c.name == 'twoFactorLabel')].value;
                }
                let totp = new OTPAuth.TOTP({
                    issuer: issuer,//"native.software",
                    label: label,//"nativesoftware",
                    algorithm: "SHA1",
                    digits: 6,
                    secret: base32_secret,
                });
                let otpauth_url = totp.toString();
                let sql = `UPDATE users SET otpAuthUrl = '` + otpauth_url + `', baseSecret='` + base32_secret + `',isTwoFactorEnable = true  WHERE id = ` + userId;
                let result = await header.query(sql);
                if (result && result.affectedRows >= 0) {
                    let getSql = "SELECT * FROM users WHERE  id =" + userId;
                    let getResult = await header.query(getSql);
                    let successResult = new ResultSuccess(200, true, 'Generate OTP Successfully', getResult, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "users.generateOTP() Error", new Error('Error While update status'), '');
                    next(errorResult);
                }
            } else {
                let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
                next(errorResult);
            }
        } else {
            await header.rollback();
            let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'users.generateOTP() Exception', error, '');
        next(errorResult);
    }
}

const validateOTP = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Generate OTP');
        let requiredFields = ['token'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let userId = authorizationResult.currentUser.id;
                let sql = `SELECT * FROM users WHERE id = ` + userId;
                let result = await header.query(sql);
                if (result && result.length > 0) {
                    let sysFalgSql = `SELECT * FROM systemflags WHERE flagGroupId = 10`;
                    let sysFalgResult = await header.query(sysFalgSql);
                    let issuer = "";
                    let label = "";
                    if (sysFalgResult && sysFalgResult.length > 0) {
                        issuer = sysFalgResult[sysFalgResult.findIndex((c: any) => c.name == 'twoFactorIssuer')].value;
                        label = sysFalgResult[sysFalgResult.findIndex((c: any) => c.name == 'twoFactorLabel')].value;
                    }
                    let totp = new OTPAuth.TOTP({
                        issuer: issuer,//"native.software",
                        label: label,//"nativesoftware",
                        algorithm: "SHA1",
                        digits: 6,
                        secret: result[0].baseSecret!,
                    });
                    const { token } = req.body;
                    let delta = totp.validate({ token, window: 1 });
                    if (delta === null) {
                        let errorResult = new ResultError(401, true, "Token Invalid", new Error("Token Invalid"), '');
                        next(errorResult);
                    } else {
                        let successResult = new ResultSuccess(200, true, 'Token is Valid', result, 1, authorizationResult.token);
                        return res.status(200).send(successResult);
                    }
                } else {
                    let errorResult = new ResultError(400, true, "User not available", new Error('User not available'), '');
                    next(errorResult);
                }
            } else {
                let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
                next(errorResult);
            }
        } else {
            await header.rollback();
            let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'users.generateOTP() Exception', error, '');
        next(errorResult);
    }
}

const resetAuthenticationOTP = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Reset Authentiacation');
        let requiredFields = [''];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let userId = authorizationResult.currentUser.id;
                const base32_secret = generateRandomBase32();
                let sysFalgSql = `SELECT * FROM systemflags WHERE flagGroupId = 10`;
                let sysFalgResult = await header.query(sysFalgSql);
                let issuer = "";
                let label = "";
                if (sysFalgResult && sysFalgResult.length > 0) {
                    issuer = sysFalgResult[sysFalgResult.findIndex((c: any) => c.name == 'twoFactorIssuer')].value;
                    label = sysFalgResult[sysFalgResult.findIndex((c: any) => c.name == 'twoFactorLabel')].value;
                }
                let totp = new OTPAuth.TOTP({
                    issuer: issuer,//"native.software",
                    label: label,//"nativesoftware",
                    algorithm: "SHA1",
                    digits: 6,
                    secret: base32_secret,
                });
                let otpauth_url = totp.toString();
                let sql = `UPDATE users SET otpAuthUrl = '` + otpauth_url + `', baseSecret='` + base32_secret + `',isTwoFactorEnable = true  WHERE id = ` + userId;
                let result = await header.query(sql);
                if (result && result.affectedRows >= 0) {
                    let getSql = "SELECT * FROM users WHERE  id =" + userId;
                    let getResult = await header.query(getSql);
                    let successResult = new ResultSuccess(200, true, 'Reset Authentiacation OTP Successfully', getResult, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "users.generateOTP() Error", new Error('Error While update status'), '');
                    next(errorResult);
                }
            } else {
                let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
                next(errorResult);
            }
        } else {
            await header.rollback();
            let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'users.generateOTP() Exception', error, '');
        next(errorResult);
    }
}

export default {
    insertUser, login, getAllUsers, getUserDetailById, updateUser, validateToken, resetPassword, activeInactiveUsers, forgotPassword, verifyforgotPasswordLink, blockUser, deleteUser
    , updateFCMToken, updateEmail, updatePassword
    // , sendAuthenticationCodeToEmail, verifyAuthenticationCode
    , updateAuthenticationStatus, changeEmail, changePassword, generateOTP, validateOTP, resetAuthenticationOTP
};