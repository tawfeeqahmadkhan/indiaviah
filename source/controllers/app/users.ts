import { NextFunction, query, request, Request, Response } from 'express';
import bcryptjs from 'bcryptjs';
import logging from "../../config/logging";
import config from "../../config/config";
import header from "../../middleware/apiHeader";
import { ResultSuccess } from '../../classes/response/resultsuccess';
import { ResultError } from '../../classes/response/resulterror';
import signJWT from '../../function/signJTW';
import createRefreshToken from '../../function/refreshToken';
import userBlock from './userBlock';
import { Users } from '../../classes/output/admin/users';
import jwt from 'jsonwebtoken';
import notificationContainer from './../notifications';


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

const verifyEmailContact = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Verify Email and Contact');
        let message = "";
        let sql = `SELECT * FROM users `;
        if (req.body.email) {
            if (!sql.includes(` WHERE `)) {
                sql += ` WHERE `;
            } else {
                sql += ` AND `;
            }
            sql += ` LOWER(email) = '` + req.body.email.toLowerCase() + `' `;
        }
        if (req.body.contactNo) {
            if (!sql.includes(` WHERE `)) {
                sql += ` WHERE `;
            } else {
                sql += ` OR `;
            }
            sql += ` contactNo = '` + req.body.contactNo + `' `;
        }
        let result = await header.query(sql);
        if (result && result.length > 0) {
            if (req.body.email && !req.body.contactNo) {
                if (req.body.email.toLowerCase() == result[0].email.toLowerCase()) {
                    message = "Email Already Exist";
                }
            }
            if (req.body.contactNo && !req.body.email) {
                if (req.body.contactNo == result[0].contactNo) {
                    message = "ContactNo Already Exist";
                }
            }
            if (req.body.contactNo && req.body.email) {
                if (req.body.email.toLowerCase() == result[0].email.toLowerCase()) {
                    message = "Email Already Exist";
                }
                if (req.body.contactNo == result[0].contactNo) {
                    if (message) {
                        message += " and ContactNo Already Exist change both";
                    } else {
                        message = "ContactNo Already Exist";
                    }
                }
            }
            let errorResult = new ResultError(203, true, message, new Error(message), '');
            next(errorResult);
            // let successResult = new ResultSuccess(200, true, message, result, 1, "null");
            // return res.status(200).send(successResult);
        } else {
            let successResult = new ResultSuccess(200, true, message, [], 1, "null");
            return res.status(200).send(successResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'users.getUsers() Exception', error, '');
        next(errorResult);
    }
};

const getAuthProvider = async (searchString: any) => {
    let result;
    try {
        let sql = "SELECT * FROM authproviders WHERE isActive = 1 AND isDelete = 0";

        if (searchString != undefined) {
            if (!sql.includes("WHERE")) {
                sql += " WHERE ";
            } else {
                sql += " AND ";
            }
            sql += " (providerName LIKE '%" + searchString + "%')";
        }
        result = await header.query(sql);
        result = JSON.parse(JSON.stringify(result));
    } catch (err) {
        result = err;
    }
    return result;
};

const addUserAuthData = async (body: any) => {
    let result;
    try {
        body.description = body.description ? body.description : '';
        let sql = `INSERT INTO userauthdata (userId, oAuthUserId, oAuthUserName, oAuthUserPicUrl, oAuthAccessToken, authProviderId, description) VALUES (` + body.userId + `,'` + body.oAuthUserId + `','` + body.oAuthUserName + `','` + body.oAuthUserPicUrl + `','` + body.oAuthAccessToken + `',` + body.authProviderId + `,'` + body.description + `')`
        let result = await header.query(sql);
        if (result.affectedRows > 0) {
            result = JSON.parse(JSON.stringify(result));
        } else {
            result = JSON.parse(JSON.stringify(result));
        }
    } catch (error) {
        return error;
    }
    return result;
};

const updateUserAuthLoginData = async (body: any) => {
    let result;
    try {
        let updatedDate = new Date(new Date().toUTCString());
        let sql = `UPDATE userauthdata SET  oAuthAccessToken =  '` + body.oAuthAccessToken + `', oAuthUserPicUrl = '` + body.oAuthUserPicUrl + `',authProviderId = ` + body.authProviderId + `, modifiedDate = '` + updatedDate + `' WHERE oAuthUserId = '` + body.oAuthUserId + `' AND userId = ` + body.userId + ``;
        result = await header.query(sql);
        if (result.changedRows > 0) {
            result = JSON.parse(JSON.stringify(result));
        }
    } catch (error: any) {
        return error;
    }
    return result;
};

const signUp = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'SignUp');
        let insertRefTokenResult;
        let deviceDetailResult;
        let requiredFields = ['email', 'contactNo', 'password'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let userDevice = authorizationResult.currentUserDevice;
                let appId: number;
                if (userDevice.app == 'MatrimonyAdmin') {
                    appId = 1;
                } else if (userDevice.app == 'MatrimonyAndroid') {
                    appId = 2;
                } else {
                    appId = 3;
                }
                req.body.imageId = req.body.imageId ? req.body.imageId : null;
                await header.beginTransaction()
                let checkEmail = `SELECT * FROM users WHERE email = '` + req.body.email + `'`;
                let checkEmailResult = await header.query(checkEmail);
                if (checkEmailResult && checkEmailResult.length > 0) {
                    await header.rollback();
                    let successResult = 'Email Already Inserted';
                    return res.status(200).send(successResult);
                } else {
                    bcryptjs.hash(req.body.password, 10, async (hashError, hash) => {
                        if (hashError) {
                            return res.status(401).json({
                                message: hashError.message,
                                error: hashError
                            });
                        }
                        let sql = `INSERT INTO users(contactNo, email, password, isDisable, referalUserId) VALUES ('` + req.body.contactNo + `','` + req.body.email + `','` + hash + `', 0,` + (req.body.referalUserId ? req.body.referalUserId : null) + `)`;
                        let result = await header.query(sql);
                        if (result && result.insertId > 0) {
                            let userId = result.insertId;
                            let userRoleSql = `INSERT INTO userroles(userId, roleId) VALUES (` + userId + `, 2) `;
                            result = await header.query(userRoleSql);
                            if (result && result.affectedRows > 0) {
                                if (userDevice) {
                                    userDevice.apiCallTime = userDevice.apiCallTime ? userDevice.apiCallTime : '';
                                    let deviceDetailSql = `INSERT INTO userdevicedetail(userId, applicationId, deviceId, fcmToken, deviceLocation, deviceManufacturer, deviceModel, apiCallTime) 
                                    VALUES(` + userId + `,` + appId + `,'` + userDevice.deviceId + `','` + userDevice.fcmToken + `','` + userDevice.deviceLocation + `','` + userDevice.deviceManufacturer + `','` + userDevice.deviceModel + `','` + userDevice.apiCallTime + `')`;
                                    deviceDetailResult = await header.query(deviceDetailSql);
                                }
                                let userFlag = await header.query(`SELECT * FROM userflags`);
                                if (userFlag && userFlag.length > 0) {
                                    for (let index = 0; index < userFlag.length; index++) {
                                        let userFlagSql = `INSERT INTO userflagvalues(userId, userFlagId, userFlagValue) VALUES (` + userId + `, ` + userFlag[index].id + `, ` + userFlag[index].defaultValue + `)`
                                        let userFlagSqlResult = await header.query(userFlagSql);
                                    }
                                }
                                let userPerDetailSql = `SELECT u.id, u.firstName, u.middleName, u.lastName, u.gender, u.email, u.contactNo
                                , upd.birthDate, upd.languages, upd.eyeColor, upd.expectation, upd.aboutMe, upd.weight, upd.profileForId, pf.name as profileForName
                                , img.imageUrl, r.name as religion, ms.name as maritalStatus, c.name as community, o.name as occupation, e.name as education, sc.name as subCommunity, ai.value as annualIncome
                                , d.name as diet, h.name as height
                                , addr.addressLine1, addr.addressLine2, addr.pincode, addr.cityId, addr.districtId, addr.stateId, addr.countryId
                                , cit.name as cityName, ds.name as districtName, st.name as stateName, cou.name as countryName
                                , em.name as employmentType, DATE_FORMAT(FROM_DAYS(DATEDIFF(now(),upd.birthDate)), '%Y')+0 AS age
                                FROM users u
                                LEFT JOIN userroles ur ON ur.userId = u.id
                                LEFT JOIN images img ON img.id = u.imageId
                                LEFT JOIN userpersonaldetail upd ON upd.userId = u.id
                                LEFT JOIN religion r ON r.id = upd.religionId
                                LEFT JOIN maritalstatus ms ON ms.id = upd.maritalStatusId
                                LEFT JOIN community c ON c.id = upd.communityId
                                LEFT JOIN occupation o ON o.id = upd.occupationId
                                LEFT JOIN education e ON e.id = upd.educationId
                                LEFT JOIN subcommunity sc ON sc.id = upd.subCommunityId
                                LEFT JOIN annualincome ai ON ai.id = upd.annualIncomeId
                                LEFT JOIN diet d ON d.id = upd.dietId
                                LEFT JOIN height h ON h.id = upd.heightId
                                LEFT JOIN addresses addr ON addr.id = upd.addressId
                                LEFT JOIN cities cit ON addr.cityId = cit.id
                                LEFT JOIN districts ds ON addr.districtId = ds.id
                                LEFT JOIN state st ON addr.stateId = st.id
                                LEFT JOIN countries cou ON addr.countryId = cou.id
                                LEFT JOIN employmenttype em ON em.id = upd.employmenttypeId
                                LEFT JOIN profilefor pf ON pf.id = upd.profileForId
                                 WHERE ur.roleId = 2 AND u.id =  ` + userId + ``;
                                let userResult: any = await header.query(userPerDetailSql);
                                let signJWTResult: any = await signJWT(userResult[0]);
                                if (signJWTResult && signJWTResult.token) {
                                    userResult[0].token = signJWTResult.token;
                                    let refreshToken = await createRefreshToken(userResult[0]);
                                    //insert refresh token
                                    let insertRefreshTokenSql = `INSERT INTO userrefreshtoken(userId, refreshToken, expireAt) VALUES(?,?,?)`;
                                    insertRefTokenResult = await header.query(insertRefreshTokenSql, [userResult[0].id, refreshToken.token, refreshToken.expireAt]);
                                    if (insertRefTokenResult && insertRefTokenResult.affectedRows > 0) {
                                        userResult[0].refreshToken = refreshToken.token;

                                        let userflagvalues = `SELECT ufv.*, uf.flagName, uf.displayName FROM userflagvalues ufv
                                        LEFT JOIN userflags uf ON uf.id = ufv.userFlagId
                                        WHERE ufv.userId = ` + userId + ``;
                                        userResult[0].userFlags = await header.query(userflagvalues);

                                        var authProvider = await getAuthProvider(req.body.oAuthProviderName);
                                        if (authProvider.length > 0 && req.body.oAuthUserId) {
                                            let data = {
                                                userId: userId,
                                                oAuthUserId: req.body.oAuthUserId,
                                                oAuthUserName: req.body.oAuthUserName,
                                                oAuthUserPicUrl: req.body.oAuthUserPicUrl,
                                                oAuthAccessToken: req.body.oAuthAccessToken,
                                                authProviderId: authProvider[0].id,
                                                description: req.body.description ? req.body.description : ''
                                            };
                                            let userOauthDataResult: any = await addUserAuthData(data);
                                            if (userOauthDataResult && userOauthDataResult.affectedRows <= 0) {
                                                await header.rollback();
                                            }
                                        }

                                        let todayDate = new Date();
                                        let date = new Date(todayDate).getFullYear() + "-" + ("0" + (new Date(todayDate).getMonth() + 1)).slice(-2) + "-" + ("0" + new Date(todayDate).getDate()).slice(-2) + "";

                                        let userPackages = `SELECT up.*, p.name as packageName, td.id as timeDurationId, td.value, p.weightage FROM userpackage up
                                        LEFT JOIN package p ON p.id = up.packageId
                                        LEFT JOIN packageduration pd ON pd.id = up.packageDurationId
                                        LEFT JOIN timeduration td ON td.id = pd.timeDurationId
                                        WHERE up.userId = ` + userId + ` AND DATE(up.startDate) <= DATE(CURRENT_TIMESTAMP()) AND DATE(up.endDate) >= DATE(CURRENT_TIMESTAMP())
                                        order by p.weightage DESC`;
                                        let userPackage = await header.query(userPackages);
                                        if (userPackage && userPackage.length > 0) {
                                            for (let k = 0; k < userPackage.length; k++) {
                                                let packageFacility = await header.query(`SELECT pf.*, pff.name FROM packagefacility pf
                                                LEFT JOIN premiumfacility pff ON pff.id = pf.premiumFacilityId
                                                 WHERE pf.packageId = ` + userPackage[k].packageId);
                                                userPackage[k].packageFacility = packageFacility;
                                            }
                                        }
                                        userResult[0].userPackage = userPackage[0];

                                        // let minAge = await header.query(`SELECT min(DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0) as minAge
                                        //     FROM users u
                                        //     LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                                        //     LEFT JOIN userroles ur ON ur.userId = u.id
                                        //     WHERE ur.roleId = 2 AND u.id != ` + userResult[0].id + ` AND (upa.userId = u.id) AND u.id NOT IN (select userBlockId from userblock where userId = ` + userResult[0].id + `)`);
                                        // let maxAge = await header.query(`SELECT max(DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0) as maxAge
                                        //     FROM users u
                                        //     LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                                        //     LEFT JOIN userroles ur ON ur.userId = u.id
                                        //     WHERE ur.roleId = 2 AND u.id != ` + userResult[0].id + ` AND (upa.userId = u.id) AND u.id NOT IN (select userBlockId from userblock where userId = ` + userResult[0].id + `)`);

                                        // let occupationSql = `SELECT * FROM occupation WHERE isActive = 1 AND isDelete = 0`;
                                        // let occupationResult = await header.query(occupationSql);

                                        // let educationSql = `SELECT * FROM education WHERE isActive = 1 AND isDelete = 0`;
                                        // let educationResult = await header.query(educationSql);

                                        // let maritalStatusSql = `SELECT * FROM maritalstatus WHERE isActive = 1 AND isDelete = 0`;
                                        // let maritalStatusResult = await header.query(maritalStatusSql);

                                        // let religionSql = `SELECT * FROM religion WHERE isActive = 1 AND isDelete = 0`;
                                        // let religionResult = await header.query(religionSql);

                                        // let communitySql = `SELECT * FROM community WHERE isActive = 1 AND isDelete = 0`;
                                        // let communityResult = await header.query(communitySql);

                                        // let subCommunitySql = `SELECT * FROM subcommunity WHERE isActive = 1 AND isDelete = 0`;
                                        // let subCommunityResult = await header.query(subCommunitySql);

                                        // let dietSql = `SELECT * FROM diet WHERE isActive = 1 AND isDelete = 0`;
                                        // let dietResult = await header.query(dietSql);

                                        // let heightSql = `SELECT * FROM height WHERE isActive = 1 AND isDelete = 0 order by name`;
                                        // let heightResult = await header.query(heightSql);

                                        // let annualIncomeSql = `SELECT * FROM annualincome WHERE isActive = 1 AND isDelete = 0`;
                                        // let annualIncomeResult = await header.query(annualIncomeSql);

                                        // let employmentTypeSql = `SELECT * FROM employmenttype WHERE isActive = 1 AND isDelete = 0`;
                                        // let employmentTypeResult = await header.query(employmentTypeSql);

                                        // let documentTypeSql = `SELECT * FROM documenttype WHERE isActive = 1 AND isDelete = 0`;
                                        // let documentTypeResult = await header.query(documentTypeSql);

                                        // userResult[0].masterEntryData = {
                                        //     "occupation": occupationResult,
                                        //     "education": educationResult,
                                        //     "maritalStatus": maritalStatusResult,
                                        //     "religion": religionResult,
                                        //     "community": communityResult,
                                        //     "subCommunity": subCommunityResult,
                                        //     "diet": dietResult,
                                        //     "height": heightResult,
                                        //     "annualIncome": annualIncomeResult,
                                        //     "employmentType": employmentTypeResult,
                                        //     "maxAge": maxAge[0].maxAge,
                                        //     "minAge": minAge[0].minAge,
                                        //     "documentType": documentTypeResult
                                        // }

                                        userResult[0].isVerified = false;
                                        let isVerified = true;
                                        let documentsSql = `SELECT ud.*, dt.name as documentTypeName FROM userdocument ud INNER JOIN documenttype dt ON dt.id = ud.documentTypeId WHERE userId = ` + userResult[0].id;
                                        let documentsResult = await header.query(documentsSql);
                                        userResult[0].userDocuments = documentsResult;
                                        if (documentsResult && documentsResult.length > 0) {
                                            for (let j = 0; j < documentsResult.length; j++) {
                                                if (documentsResult[j].isRequired && !documentsResult[j].isVerified) {
                                                    isVerified = false;
                                                }
                                            }
                                        } else {
                                            isVerified = false;
                                        }
                                        userResult[0].isVerifiedProfile = isVerified;
                                        if (req.body.password) {
                                            userResult[0].isOAuth = false;
                                        } else {
                                            userResult[0].isOAuth = true;
                                        }

                                        userResult[0].isAppleLogin = authProvider[0].id == 3 ? true : false;

                                        userResult[0].userWalletAmount = 0;
                                        let getUserWalletSql = `SELECT * FROM userwallets WHERE userId = ` + userResult[0].id;
                                        let getUserWalletResult = await header.query(getUserWalletSql);
                                        if (getUserWalletResult && getUserWalletResult.length > 0) {
                                            userResult[0].userWalletAmount = getUserWalletResult[0].amount
                                        }

                                        await header.commit();
                                        let successResult = new ResultSuccess(200, true, 'Login User', userResult, 1, "");
                                        return res.status(200).send(successResult);
                                    } else {
                                        await header.rollback();
                                        let errorResult = new ResultError(400, true, "users.signUp() Error", new Error('Error While Login'), '');
                                        next(errorResult);
                                    }
                                } else {
                                    await header.rollback();
                                    return res.status(401).json({
                                        message: 'Unable to Sign JWT',
                                        error: signJWTResult.error
                                    });
                                }
                            } else {
                                await header.rollback();
                                let errorResult = new ResultError(400, true, "users.signUp() Error", new Error('Error While Inserting Data'), '');
                                next(errorResult);
                            }
                        } else {
                            await header.rollback();
                            let errorResult = new ResultError(400, true, "users.signUp() Error", new Error('Error While Inserting Data'), '');
                            next(errorResult);
                        }
                    });
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
        let errorResult = new ResultError(500, true, 'users.signUp() Exception', error, '');
        next(errorResult);
    }
};

const login = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Login');
        if (req.body.isOAuth) {
            let requiredFields = ['email'];
            let validationResult = header.validateRequiredFields(req, requiredFields);
            if (validationResult && validationResult.statusCode == 200) {
                let authorizationResult = await header.validateAuthorization(req, res, next);
                if (authorizationResult.statusCode == 200) {
                    let userDevice = authorizationResult.currentUserDevice;
                    let deviceDetailResult;
                    let appId: number;
                    if (userDevice.app == 'MatrimonyAdmin') {
                        appId = 1;
                    } else if (userDevice.app == 'MatrimonyAndroid') {
                        appId = 2;
                    } else {
                        appId = 3;
                    }
                    await header.beginTransaction();
                    let userId: number;
                    let insertRefTokenResult;

                    let _UserData;
                    let _ValidateUser = await header.query(`SELECT * FROM users WHERE email = '` + req.body.email + `'`);

                    // checking if this email already registered using simple email password method
                    if (_ValidateUser && _ValidateUser.length > 0 && _ValidateUser[0].password != undefined) {
                        let successResult = new ResultSuccess(200, true, 'This email is already registered using a password', [], 1, "");
                        return res.status(200).send(successResult);
                    }

                    if (_ValidateUser && _ValidateUser.length <= 0) {
                        let sql = `INSERT INTO users(email, isDisable, referalUserId) VALUES ('` + req.body.email + `', 0, ` + (req.body.referalUserId ? req.body.referalUserId : null) + `)`;
                        let result = await header.query(sql);
                        if (result && result.insertId > 0) {
                            let userId = result.insertId;
                            let userRoleSql = `INSERT INTO userroles(userId, roleId) VALUES (` + userId + `, 2) `;
                            result = await header.query(userRoleSql);
                            if (result && result.affectedRows > 0) {
                                if (userDevice) {
                                    userDevice.apiCallTime = userDevice.apiCallTime ? userDevice.apiCallTime : '';
                                    let deviceDetailSql = `INSERT INTO userdevicedetail(userId, applicationId, deviceId, fcmToken, deviceLocation, deviceManufacturer, deviceModel, apiCallTime) VALUES(` + userId + `,` + appId + `,'` + userDevice.deviceId + `','` + userDevice.fcmToken + `','` + userDevice.deviceLocation + `','` + userDevice.deviceManufacturer + `','` + userDevice.deviceModel + `','` + userDevice.apiCallTime + `')`;
                                    deviceDetailResult = await header.query(deviceDetailSql);
                                }
                                let userFlag = await header.query(`SELECT * FROM userflags`);
                                if (userFlag && userFlag.length > 0) {
                                    for (let index = 0; index < userFlag.length; index++) {
                                        let userFlagSql = `INSERT INTO userflagvalues(userId, userFlagId, userFlagValue) VALUES (` + userId + `, ` + userFlag[index].id + `, ` + userFlag[index].defaultValue + `)`
                                        let userFlagSqlResult = await header.query(userFlagSql);
                                    }
                                }

                                var authProvider = await getAuthProvider(req.body.oAuthProviderName);
                                if (authProvider.length > 0) {
                                    let data = {
                                        userId: userId,
                                        oAuthUserId: req.body.oAuthUserId,
                                        oAuthUserName: req.body.oAuthUserName,
                                        oAuthUserPicUrl: req.body.oAuthUserPicUrl,
                                        oAuthAccessToken: req.body.oAuthAccessToken,
                                        authProviderId: authProvider[0].id,
                                        description: req.body.description ? req.body.description : ''
                                    };
                                    let userOauthDataResult: any = await addUserAuthData(data);
                                    if (userOauthDataResult && userOauthDataResult.affectedRows <= 0) {
                                        await header.rollback();
                                    }
                                }

                                let userPerDetailSql = `SELECT u.id, u.firstName, u.middleName, u.lastName, u.gender, u.email, u.contactNo
                                , upd.birthDate, upd.languages, upd.eyeColor, upd.expectation, upd.aboutMe, upd.weight, upd.profileForId, pf.name as profileForName
                                , img.imageUrl, r.name as religion, ms.name as maritalStatus, c.name as community, o.name as occupation, e.name as education, sc.name as subCommunity, ai.value as annualIncome
                                , d.name as diet, h.name as height
                                , addr.addressLine1, addr.addressLine2, addr.pincode, addr.cityId, addr.districtId, addr.stateId, addr.countryId
                                , cit.name as cityName, ds.name as districtName, st.name as stateName, cou.name as countryName
                                , em.name as employmentType, DATE_FORMAT(FROM_DAYS(DATEDIFF(now(),upd.birthDate)), '%Y')+0 AS age
                                , addr.latitude, addr.longitude
                                    FROM users u
                                    LEFT JOIN userroles ur ON ur.userId = u.id
                                    LEFT JOIN images img ON img.id = u.imageId
                                    LEFT JOIN userpersonaldetail upd ON upd.userId = u.id
                                    LEFT JOIN religion r ON r.id = upd.religionId
                                    LEFT JOIN maritalstatus ms ON ms.id = upd.maritalStatusId
                                    LEFT JOIN community c ON c.id = upd.communityId
                                    LEFT JOIN occupation o ON o.id = upd.occupationId
                                    LEFT JOIN education e ON e.id = upd.educationId
                                    LEFT JOIN subcommunity sc ON sc.id = upd.subCommunityId
                                    LEFT JOIN annualincome ai ON ai.id = upd.annualIncomeId
                                    LEFT JOIN diet d ON d.id = upd.dietId
                                    LEFT JOIN height h ON h.id = upd.heightId
                                    LEFT JOIN addresses addr ON addr.id = upd.addressId
                                    LEFT JOIN cities cit ON addr.cityId = cit.id
                                    LEFT JOIN districts ds ON addr.districtId = ds.id
                                    LEFT JOIN state st ON addr.stateId = st.id
                                    LEFT JOIN countries cou ON addr.countryId = cou.id
                                    LEFT JOIN employmenttype em ON em.id = upd.employmenttypeId
                                    LEFT JOIN profilefor pf ON pf.id = upd.profileForId
                                     WHERE ur.roleId = 2
                                      AND u.id =  ` + userId + ``;
                                let userResult = await header.query(userPerDetailSql);
                                let signJWTResult: any = await signJWT(userResult[0]);
                                if (signJWTResult && signJWTResult.token) {
                                    userResult[0].token = signJWTResult.token;
                                    let refreshToken = await createRefreshToken(userResult[0]);
                                    //insert refresh token
                                    let insertRefreshTokenSql = `INSERT INTO userrefreshtoken(userId, refreshToken, expireAt) VALUES(?,?,?)`;
                                    insertRefTokenResult = await header.query(insertRefreshTokenSql, [userResult[0].id, refreshToken.token, refreshToken.expireAt]);
                                    if (insertRefTokenResult && insertRefTokenResult.affectedRows > 0) {
                                        userResult[0].refreshToken = refreshToken.token;

                                        let userflagvalues = `SELECT ufv.*, uf.flagName, uf.displayName FROM userflagvalues ufv
                                            LEFT JOIN userflags uf ON uf.id = ufv.userFlagId
                                            WHERE ufv.userId = ` + userId + ``;
                                        userResult[0].userFlags = await header.query(userflagvalues);

                                        let todayDate = new Date();
                                        let date = new Date(todayDate).getFullYear() + "-" + ("0" + (new Date(todayDate).getMonth() + 1)).slice(-2) + "-" + ("0" + new Date(todayDate).getDate()).slice(-2) + "";

                                        let userPackages = `SELECT up.*, p.name as packageName, td.id as timeDurationId, td.value FROM userpackage up
                                            LEFT JOIN package p ON p.id = up.packageId
                                            LEFT JOIN packageduration pd ON pd.id = up.packageDurationId
                                            LEFT JOIN timeduration td ON td.id = pd.timeDurationId
                                                WHERE up.userId = ` + userId + ` order by createdDate DESC`;
                                        let userPackage = await header.query(userPackages);
                                        if (userPackage && userPackage.length > 0) {
                                            for (let k = 0; k < userPackage.length; k++) {
                                                let packageFacility = await header.query(`SELECT pf.*, pff.name FROM packagefacility pf
                                                    LEFT JOIN premiumfacility pff ON pff.id = pf.premiumFacilityId
                                                     WHERE pf.packageId = ` + userPackage[k].packageId);
                                                userPackage[k].packageFacility = packageFacility;
                                            }
                                        }
                                        userResult[0].userPackage = userPackage[0];

                                        // let minAge = await header.query(`SELECT min(DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0) as minAge
                                        //         FROM users u
                                        //         LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                                        //         LEFT JOIN userroles ur ON ur.userId = u.id
                                        //         WHERE ur.roleId = 2 AND u.id != ` + userResult[0].id + ` AND (upa.userId = u.id) AND u.id NOT IN (select userBlockId from userblock where userId = ` + userResult[0].id + `)`);
                                        // let maxAge = await header.query(`SELECT max(DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0) as maxAge
                                        //         FROM users u
                                        //         LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                                        //         LEFT JOIN userroles ur ON ur.userId = u.id
                                        //         WHERE ur.roleId = 2 AND u.id != ` + userResult[0].id + ` AND (upa.userId = u.id) AND u.id NOT IN (select userBlockId from userblock where userId = ` + userResult[0].id + `)`);

                                        // let ageList = [];
                                        // for (let i = 18; i <= 60; i++) {
                                        //     ageList.push(i)
                                        // }

                                        // let cityName = await header.query(`select (cityName) FROM addresses where cityName is not null or cityName !='' group by cityName  having  cityName !=''`)

                                        // let occupationSql = `SELECT * FROM occupation WHERE isActive = 1 AND isDelete = 0`;
                                        // let occupationResult = await header.query(occupationSql);

                                        // let educationSql = `SELECT * FROM education WHERE isActive = 1 AND isDelete = 0`;
                                        // let educationResult = await header.query(educationSql);

                                        // let maritalStatusSql = `SELECT * FROM maritalstatus WHERE isActive = 1 AND isDelete = 0`;
                                        // let maritalStatusResult = await header.query(maritalStatusSql);

                                        // let religionSql = `SELECT * FROM religion WHERE isActive = 1 AND isDelete = 0`;
                                        // let religionResult = await header.query(religionSql);

                                        // let communitySql = `SELECT * FROM community WHERE isActive = 1 AND isDelete = 0`;
                                        // let communityResult = await header.query(communitySql);

                                        // let subCommunitySql = `SELECT * FROM subcommunity WHERE isActive = 1 AND isDelete = 0`;
                                        // let subCommunityResult = await header.query(subCommunitySql);

                                        // let dietSql = `SELECT * FROM diet WHERE isActive = 1 AND isDelete = 0`;
                                        // let dietResult = await header.query(dietSql);

                                        // let heightSql = `SELECT * FROM height WHERE isActive = 1 AND isDelete = 0 order by name`;
                                        // let heightResult = await header.query(heightSql);

                                        // let annualIncomeSql = `SELECT * FROM annualincome WHERE isActive = 1 AND isDelete = 0`;
                                        // let annualIncomeResult = await header.query(annualIncomeSql);

                                        // let employmentTypeSql = `SELECT * FROM employmenttype WHERE isActive = 1 AND isDelete = 0`;
                                        // let employmentTypeResult = await header.query(employmentTypeSql);

                                        // let documentTypeSql = `SELECT * FROM documenttype WHERE isActive = 1 AND isDelete = 0`;
                                        // let documentTypeResult = await header.query(documentTypeSql);

                                        // userResult[0].masterEntryData = {
                                        //     "occupation": occupationResult,
                                        //     "education": educationResult,
                                        //     "maritalStatus": maritalStatusResult,
                                        //     "religion": religionResult,
                                        //     "community": communityResult,
                                        //     "subCommunity": subCommunityResult,
                                        //     "diet": dietResult,
                                        //     "height": heightResult,
                                        //     "annualIncome": annualIncomeResult,
                                        //     "employmentType": employmentTypeResult,
                                        //     "maxAge": maxAge[0].maxAge,
                                        //     "minAge": minAge[0].minAge,
                                        //     "ageList": ageList,
                                        //     "cityName": cityName,
                                        //     "documentType": documentTypeResult
                                        // }

                                        userResult[0].isVerified = false;
                                        let isVerified = true;
                                        let documentsSql = `SELECT ud.*, dt.name as documentTypeName FROM userdocument ud INNER JOIN documenttype dt ON dt.id = ud.documentTypeId WHERE userId = ` + userResult[0].id;
                                        let documentsResult = await header.query(documentsSql);
                                        userResult[0].userDocuments = documentsResult;
                                        if (documentsResult && documentsResult.length > 0) {
                                            for (let j = 0; j < documentsResult.length; j++) {
                                                if (documentsResult[j].isRequired && !documentsResult[j].isVerified) {
                                                    isVerified = false;
                                                }
                                            }
                                        } else {
                                            isVerified = false;
                                        }
                                        userResult[0].isVerifiedProfile = isVerified;
                                        userResult[0].isOAuth = true;
                                        userResult[0].isAppleLogin = authProvider[0].id == 3 ? true : false;

                                        userResult[0].userWalletAmount = 0;
                                        let getUserWalletSql = `SELECT * FROM userwallets WHERE userId = ` + userResult[0].id;
                                        let getUserWalletResult = await header.query(getUserWalletSql);
                                        if (getUserWalletResult && getUserWalletResult.length > 0) {
                                            userResult[0].userWalletAmount = getUserWalletResult[0].amount
                                        }

                                        await header.commit();
                                        let successResult = new ResultSuccess(200, true, 'Login User', userResult, 1, "");
                                        return res.status(200).send(successResult);
                                    } else {
                                        await header.rollback();
                                        let errorResult = new ResultError(400, true, "users.signUp() Error", new Error('Error While Login'), '');
                                        next(errorResult);
                                    }
                                } else {
                                    await header.rollback();
                                    return res.status(401).json({
                                        message: 'Unable to Sign JWT',
                                        error: signJWTResult.error
                                    });
                                }
                            } else {
                                await header.rollback();
                                let errorResult = new ResultError(400, true, "users.signUp() Error", new Error('Error While Inserting Data'), '');
                                next(errorResult);
                            }
                        } else {
                            await header.rollback();
                            let errorResult = new ResultError(400, true, "users.signUp() Error", new Error('Error While Inserting Data'), '');
                            next(errorResult);
                        }
                    } else {
                        let isAppleLogin = false;
                        if (req.body.isAppleLogin) {
                            _UserData = await header.query(`SELECT * FROM userauthdata WHERE oAuthUserId = '` + req.body.oAuthUserId + `'`);
                            userId = _UserData[0].userId
                            isAppleLogin = true;
                        } else {
                            _UserData = await header.query(`SELECT uad.* FROM users u
                                Inner JOIN userauthdata uad ON uad.userId = u.id
                                WHERE u.email = '` + req.body.email + `' AND oAuthUserId = '` + req.body.oAuthUserId + `'`);
                            if (_UserData.length > 0) {
                                userId = _UserData[0].id
                            }

                        }

                        if (_UserData && _UserData.length <= 0) {
                            _UserData = await header.query(`SELECT * FROM users WHERE email = '` + req.body.email + `'`);

                            let checkuserflagvalues = await header.query(`SELECT * FROM userflagvalues WHERE userId = ` + _UserData[0].id);
                            if (checkuserflagvalues && checkuserflagvalues.length <= 0) {
                                let userFlag = await header.query(`SELECT * FROM userflags`);
                                if (userFlag && userFlag.length > 0) {
                                    for (let index = 0; index < userFlag.length; index++) {
                                        let userFlagSql = `INSERT INTO userflagvalues(userId, userFlagId, userFlagValue) VALUES (` + _UserData[0].id + `, ` + userFlag[index].id + `, ` + userFlag[index].defaultValue + `)`
                                        let userFlagSqlResult = await header.query(userFlagSql);
                                    }
                                }
                            }

                            var authProvider = await getAuthProvider(req.body.oAuthProviderName);
                            if (authProvider.length > 0) {
                                let data = {
                                    userId: _UserData[0].id,
                                    oAuthUserId: req.body.oAuthUserId,
                                    oAuthUserName: req.body.oAuthUserName,
                                    oAuthUserPicUrl: req.body.oAuthUserPicUrl,
                                    oAuthAccessToken: req.body.oAuthAccessToken,
                                    authProviderId: authProvider[0].id,
                                    description: req.body.description ? req.body.description : ''
                                };
                                let userOauthDataResult: any = await addUserAuthData(data);
                                if (userOauthDataResult && userOauthDataResult.affectedRows <= 0) {
                                    await header.rollback();
                                }
                            }

                        }
                        else {
                            var authProvider = await getAuthProvider(req.body.oAuthProviderName);
                            if (authProvider.length > 0) {
                                let data = {
                                    oAuthAccessToken: _UserData[0].oAuthAccessToken,
                                    oAuthUserPicUrl: _UserData[0].oAuthUserPicUrl,
                                    oAuthUserId: _UserData[0].oAuthUserId,
                                    userId: _UserData[0].userId,
                                    authProviderId: authProvider[0].id,
                                }
                                await updateUserAuthLoginData(data);
                            }
                        }

                        let result: any = [];
                        result.push(({ "id": _UserData[0].userId }));
                        userId = result[0].id;
                        let userPerDetailSql = `SELECT u.id, u.firstName, u.middleName, u.lastName, u.gender, u.email, u.contactNo
                        , upd.birthDate, upd.languages, upd.eyeColor, upd.expectation, upd.weight, upd.profileForId, pf.name as profileForName
                        , upd.aboutMe, img.imageUrl, r.name as religion, ms.name as maritalStatus, c.name as community, o.name as occupation, e.name as education, sc.name as subCommunity
                        , ai.value as annualIncome, d.name as diet, h.name as height
                        , addr.addressLine1, addr.addressLine2, addr.pincode, addr.cityId, addr.districtId, addr.stateId, addr.countryId
                        , cit.name as cityName, ds.name as districtName, st.name as stateName, cou.name as countryName
                        , em.name as employmentType, DATE_FORMAT(FROM_DAYS(DATEDIFF(now(),upd.birthDate)), '%Y')+0 AS age
                        , addr.latitude, addr.longitude
                            FROM users u
                            LEFT JOIN userroles ur ON ur.userId = u.id
                            LEFT JOIN images img ON img.id = u.imageId
                            LEFT JOIN userpersonaldetail upd ON upd.userId = u.id
                            LEFT JOIN religion r ON r.id = upd.religionId
                            LEFT JOIN maritalstatus ms ON ms.id = upd.maritalStatusId
                            LEFT JOIN community c ON c.id = upd.communityId
                            LEFT JOIN occupation o ON o.id = upd.occupationId
                            LEFT JOIN education e ON e.id = upd.educationId
                            LEFT JOIN subcommunity sc ON sc.id = upd.subCommunityId
                            LEFT JOIN annualincome ai ON ai.id = upd.annualIncomeId
                            LEFT JOIN diet d ON d.id = upd.dietId
                            LEFT JOIN height h ON h.id = upd.heightId
                            LEFT JOIN addresses addr ON addr.id = upd.addressId
                            LEFT JOIN cities cit ON addr.cityId = cit.id
                            LEFT JOIN districts ds ON addr.districtId = ds.id
                            LEFT JOIN state st ON addr.stateId = st.id
                            LEFT JOIN countries cou ON addr.countryId = cou.id
                            LEFT JOIN employmenttype em ON em.id = upd.employmenttypeId
                            LEFT JOIN profilefor pf ON pf.id = upd.profileForId
                             WHERE ur.roleId = 2
                              AND u.email =  '` + req.body.email + `' `;
                        let userResult = await header.query(userPerDetailSql);
                        if (userResult && userResult.length > 0) {
                            let checkbloclsql = `SELECT * FROM userblockrequest WHERE blockRequestUserId = ` + userResult[0].id;
                            let checkbloclResult = await header.query(checkbloclsql);
                            if (checkbloclResult && checkbloclResult.length > 0) {
                                let successResult = new ResultSuccess(401, true, 'Your account was bloacked', [], 1, "");
                                return res.status(200).send(successResult);
                            } else {
                                let signJWTResult: any = await signJWT(result[0]);
                                if (signJWTResult && signJWTResult.token) {
                                    userResult[0].token = signJWTResult.token;
                                    if (userDevice) {
                                        let checkDeviceSql = `SELECT * FROM userdevicedetail WHERE userId = ` + userId + ``;
                                        result = await header.query(checkDeviceSql);
                                        userDevice.apiCallTime = userDevice.apiCallTime ? userDevice.apiCallTime : '';
                                        if (result && result.length > 0) {
                                            let updateDetailSql = `UPDATE userdevicedetail SET userId = ` + userId + `,applicationId = ` + appId + `,deviceId = '` + userDevice.deviceId + `',fcmToken = '` + userDevice.fcmToken + `',deviceLocation = '` + userDevice.deviceLocation + `',deviceManufacturer = '` + userDevice.deviceManufacturer + `',deviceModel = '` + userDevice.deviceModel + `',apiCallTime = '` + userDevice.apiCallTime + `' WHERE userId = ` + userId;
                                            result = await header.query(updateDetailSql);
                                        } else {
                                            let insertDetailSql = `INSERT INTO userdevicedetail(userId, applicationId, deviceId, fcmToken, deviceLocation, deviceManufacturer, deviceModel, apiCallTime) VALUES(` + userId + `,` + appId + `,'` + userDevice.deviceId + `','` + userDevice.fcmToken + `','` + userDevice.deviceLocation + `','` + userDevice.deviceManufacturer + `','` + userDevice.deviceModel + `','` + userDevice.apiCallTime + `')`;
                                            result = await header.query(insertDetailSql);
                                        }
                                    }
                                    let refreshToken = await createRefreshToken(userResult[0]);
                                    //insert refresh token
                                    let insertRefreshTokenSql = `INSERT INTO userrefreshtoken(userId, refreshToken, expireAt) VALUES(?,?,?)`;
                                    insertRefTokenResult = await header.query(insertRefreshTokenSql, [userResult[0].id, refreshToken.token, refreshToken.expireAt]);
                                    if (insertRefTokenResult && insertRefTokenResult.affectedRows > 0) {
                                        userResult[0].refreshToken = refreshToken.token;

                                        let userflagvalues = `SELECT ufv.*, uf.flagName, uf.displayName FROM userflagvalues ufv
                                    LEFT JOIN userflags uf ON uf.id = ufv.userFlagId
                                    WHERE ufv.userId = ` + userId + ``;
                                        userResult[0].userFlags = await header.query(userflagvalues);

                                        let todayDate = new Date();
                                        let date = new Date(todayDate).getFullYear() + "-" + ("0" + (new Date(todayDate).getMonth() + 1)).slice(-2) + "-" + ("0" + new Date(todayDate).getDate()).slice(-2) + "";

                                        let userPackages = `SELECT up.*, p.name as packageName, td.id as timeDurationId, td.value, p.weightage FROM userpackage up
                                    LEFT JOIN package p ON p.id = up.packageId
                                    LEFT JOIN packageduration pd ON pd.id = up.packageDurationId
                                    LEFT JOIN timeduration td ON td.id = pd.timeDurationId
                                        WHERE up.userId = ` + userId + ` AND DATE(up.startDate) <+ DATE(CURRENT_TIMESTAMP()) AND DATE(up.endDate) >= DATE(CURRENT_TIMESTAMP())
                                        ORDER BY p.weightage DESC`;
                                        let userPackage = await header.query(userPackages);
                                        if (userPackage && userPackage.length > 0) {
                                            for (let k = 0; k < userPackage.length; k++) {
                                                let packageFacility = await header.query(`SELECT pf.*, pff.name FROM packagefacility pf
                                            LEFT JOIN premiumfacility pff ON pff.id = pf.premiumFacilityId
                                             WHERE pf.packageId = ` + userPackage[k].packageId);
                                                userPackage[k].packageFacility = packageFacility;
                                            }
                                        }
                                        userResult[0].userPackage = userPackage[0];

                                        //     let minAge = await header.query(`SELECT min(DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0) as minAge
                                        // FROM users u
                                        // LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                                        // LEFT JOIN userroles ur ON ur.userId = u.id
                                        // WHERE ur.roleId = 2 AND u.id != ` + userResult[0].id + ` AND (upa.userId = u.id) AND u.id NOT IN (select userBlockId from userblock where userId = ` + userResult[0].id + `)`);
                                        //     let maxAge = await header.query(`SELECT max(DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0) as maxAge
                                        // FROM users u
                                        // LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                                        // LEFT JOIN userroles ur ON ur.userId = u.id
                                        // WHERE ur.roleId = 2 AND u.id != ` + userResult[0].id + ` AND (upa.userId = u.id) AND u.id NOT IN (select userBlockId from userblock where userId = ` + userResult[0].id + `)`);

                                        //     let ageList = [];
                                        //     for (let i = 18; i <= 60; i++) {
                                        //         ageList.push(i)
                                        //     }
                                        //     let cityName = await header.query(`select (cityName) FROM addresses where cityName is not null or cityName !='' group by cityName  having  cityName !=''`)

                                        //     let occupationSql = `SELECT * FROM occupation WHERE isActive = 1 AND isDelete = 0`;
                                        //     let occupationResult = await header.query(occupationSql);

                                        //     let educationSql = `SELECT * FROM education WHERE isActive = 1 AND isDelete = 0`;
                                        //     let educationResult = await header.query(educationSql);

                                        //     let maritalStatusSql = `SELECT * FROM maritalstatus WHERE isActive = 1 AND isDelete = 0`;
                                        //     let maritalStatusResult = await header.query(maritalStatusSql);

                                        //     let religionSql = `SELECT * FROM religion WHERE isActive = 1 AND isDelete = 0`;
                                        //     let religionResult = await header.query(religionSql);

                                        //     let communitySql = `SELECT * FROM community WHERE isActive = 1 AND isDelete = 0`;
                                        //     let communityResult = await header.query(communitySql);

                                        //     let subCommunitySql = `SELECT * FROM subcommunity WHERE isActive = 1 AND isDelete = 0`;
                                        //     let subCommunityResult = await header.query(subCommunitySql);

                                        //     let dietSql = `SELECT * FROM diet WHERE isActive = 1 AND isDelete = 0`;
                                        //     let dietResult = await header.query(dietSql);

                                        //     let heightSql = `SELECT * FROM height WHERE isActive = 1 AND isDelete = 0 order by name`;
                                        //     let heightResult = await header.query(heightSql);

                                        //     let annualIncomeSql = `SELECT * FROM annualincome WHERE isActive = 1 AND isDelete = 0`;
                                        //     let annualIncomeResult = await header.query(annualIncomeSql);

                                        //     let employmentTypeSql = `SELECT * FROM employmenttype WHERE isActive = 1 AND isDelete = 0`;
                                        //     let employmentTypeResult = await header.query(employmentTypeSql);

                                        //     let documentTypeSql = `SELECT * FROM documenttype WHERE isActive = 1 AND isDelete = 0`;
                                        //     let documentTypeResult = await header.query(documentTypeSql);

                                        //     userResult[0].masterEntryData = {
                                        //         "occupation": occupationResult,
                                        //         "education": educationResult,
                                        //         "maritalStatus": maritalStatusResult,
                                        //         "religion": religionResult,
                                        //         "community": communityResult,
                                        //         "subCommunity": subCommunityResult,
                                        //         "diet": dietResult,
                                        //         "height": heightResult,
                                        //         "annualIncome": annualIncomeResult,
                                        //         "employmentType": employmentTypeResult,
                                        //         "maxAge": maxAge[0].maxAge,
                                        //         "minAge": minAge[0].minAge,
                                        //         "ageList": ageList,
                                        //         "cityName": cityName,
                                        //         "documentType": documentTypeResult
                                        //     }

                                        userResult[0].isVerified = false;
                                        let isVerified = true;
                                        let documentsSql = `SELECT ud.*, dt.name as documentTypeName FROM userdocument ud INNER JOIN documenttype dt ON dt.id = ud.documentTypeId WHERE userId = ` + userResult[0].id;
                                        let documentsResult = await header.query(documentsSql);
                                        userResult[0].userDocuments = documentsResult;
                                        if (documentsResult && documentsResult.length > 0) {
                                            for (let j = 0; j < documentsResult.length; j++) {
                                                if (documentsResult[j].isRequired && !documentsResult[j].isVerified) {
                                                    isVerified = false;
                                                }
                                            }
                                        } else {
                                            isVerified = false;
                                        }
                                        userResult[0].isVerifiedProfile = isVerified;
                                        userResult[0].isOAuth = true;
                                        userResult[0].isAppleLogin = isAppleLogin;

                                        userResult[0].userWalletAmount = 0;
                                        let getUserWalletSql = `SELECT * FROM userwallets WHERE userId = ` + userResult[0].id;
                                        let getUserWalletResult = await header.query(getUserWalletSql);
                                        if (getUserWalletResult && getUserWalletResult.length > 0) {
                                            userResult[0].userWalletAmount = getUserWalletResult[0].amount
                                        }

                                        await header.commit();
                                        let successResult = new ResultSuccess(200, true, 'Login User', userResult, 1, "");
                                        return res.status(200).send(successResult);
                                    } else {
                                        await header.rollback();
                                        let errorResult = new ResultError(400, true, "users.signUp() Error", new Error('Error While Login'), '');
                                        next(errorResult);
                                    }
                                } else {
                                    return res.status(401).json({
                                        message: 'Unable to Sign JWT',
                                        error: signJWTResult.error
                                    });
                                }
                            }
                        } else {
                            let successResult = new ResultSuccess(200, true, 'Email is incorrect!', [], 1, "");
                            return res.status(200).send(successResult);
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
        } else {
            let requiredFields = ['email', 'password'];
            let validationResult = header.validateRequiredFields(req, requiredFields);
            if (validationResult && validationResult.statusCode == 200) {
                let authorizationResult = await header.validateAuthorization(req, res, next);
                if (authorizationResult.statusCode == 200) {
                    let userDevice = authorizationResult.currentUserDevice;
                    let deviceDetailResult;
                    let appId: number;
                    if (userDevice.app == 'MatrimonyAdmin') {
                        appId = 1;
                    } else if (userDevice.app == 'MatrimonyAndroid') {
                        appId = 2;
                    } else {
                        appId = 3;
                    }
                    await header.beginTransaction();
                    let userId: number;
                    let insertRefTokenResult;

                    let sql = `SELECT u.*, ur.roleId, img.imageUrl FROM users u
                        LEFT JOIN userroles ur ON ur.userId = u.id
                        LEFT JOIN images img ON img.id =u.imageId
                        WHERE (u.email = '` + req.body.email + `' OR u.contactNo = '` + req.body.email + `') AND u.isActive = true AND ur.roleId = 2`;
                    let result = await header.query(sql);
                    let userPerDetailSql = `SELECT u.id, u.firstName, u.middleName, u.lastName, u.gender, u.email, u.contactNo, u.password
                    , upd.birthDate, upd.languages, upd.eyeColor, upd.expectation, upd.weight, upd.profileForId, pf.name as profileForName
                    , upd.aboutMe, img.imageUrl, r.name as religion, ms.name as maritalStatus, c.name as community, o.name as occupation, e.name as education, sc.name as subCommunity
                    , ai.value as annualIncome, d.name as diet, h.name as height
                    , addr.addressLine1, addr.addressLine2, addr.pincode, addr.cityId, addr.districtId, addr.stateId, addr.countryId
                    , cit.name as cityName, ds.name as districtName, st.name as stateName, cou.name as countryName
                    , em.name as employmentType, DATE_FORMAT(FROM_DAYS(DATEDIFF(now(),upd.birthDate)), '%Y')+0 AS age
                    , addr.latitude, addr.longitude
                        FROM users u
                        LEFT JOIN userroles ur ON ur.userId = u.id
                        LEFT JOIN images img ON img.id = u.imageId
                        LEFT JOIN userpersonaldetail upd ON upd.userId = u.id
                        LEFT JOIN religion r ON r.id = upd.religionId
                        LEFT JOIN maritalstatus ms ON ms.id = upd.maritalStatusId
                        LEFT JOIN community c ON c.id = upd.communityId
                        LEFT JOIN occupation o ON o.id = upd.occupationId
                        LEFT JOIN education e ON e.id = upd.educationId
                        LEFT JOIN subcommunity sc ON sc.id = upd.subCommunityId
                        LEFT JOIN annualincome ai ON ai.id = upd.annualIncomeId
                        LEFT JOIN diet d ON d.id = upd.dietId
                        LEFT JOIN height h ON h.id = upd.heightId
                        LEFT JOIN addresses addr ON addr.id = upd.addressId
                        LEFT JOIN cities cit ON addr.cityId = cit.id
                        LEFT JOIN districts ds ON addr.districtId = ds.id
                        LEFT JOIN state st ON addr.stateId = st.id
                        LEFT JOIN countries cou ON addr.countryId = cou.id
                        LEFT JOIN employmenttype em ON em.id = upd.employmenttypeId
                        LEFT JOIN profilefor pf ON pf.id = upd.profileForId
                         WHERE ur.roleId = 2
                          AND (u.email = '` + req.body.email + `' OR u.contactNo = '` + req.body.email + `') `;
                    let userResult = await header.query(userPerDetailSql);

                    // checking if this email already registered using google or mobile and otp method
                    if (userResult && userResult.length > 0 && req.body.email.includes("@") && userResult[0].password == undefined) {
                        let successResult = new ResultSuccess(200, true, 'This email is already registered using google or mobile and OTP', [], 1, "");
                        return res.status(200).send(successResult);
                    }

                    if (result && result.length > 0) {
                        let checkbloclsql = `SELECT * FROM userblockrequest WHERE blockRequestUserId = ` + result[0].id;
                        let checkbloclResult = await header.query(checkbloclsql);
                        if (checkbloclResult && checkbloclResult.length > 0) {
                            let successResult = new ResultSuccess(401, true, 'Your account was bloacked', [], 1, "");
                            return res.status(200).send(successResult);
                        } else {
                            if (result[0].isDisable) {
                                let errorResult = new ResultError(400, true, "users.login() Error", new Error('Your profile was block by Admin. You cannot login.'), '');
                                next(errorResult);
                            } else {
                                userId = result[0].id;
                                if (result && result.length > 0) {
                                    if (result[0].password == null) {
                                        let successResult = new ResultSuccess(200, true, 'This mobile no. is registered using OTP or google', [], 1, "");
                                        return res.status(200).send(successResult);
                                    }
                                    bcryptjs.compare(req.body.password, result[0].password, async (error, hashresult: any) => {
                                        if (hashresult == false) {
                                            return res.status(401).json({
                                                message: 'Password Mismatch'
                                            });
                                        } else if (hashresult) {
                                            let signJWTResult: any = await signJWT(result[0]);
                                            if (signJWTResult && signJWTResult.token) {
                                                userResult[0].token = signJWTResult.token;
                                                if (userDevice) {
                                                    let checkDeviceSql = `SELECT * FROM userdevicedetail WHERE userId = ` + userId + ``;
                                                    result = await header.query(checkDeviceSql);
                                                    userDevice.apiCallTime = userDevice.apiCallTime ? userDevice.apiCallTime : '';
                                                    if (result && result.length > 0) {
                                                        let updateDetailSql = `UPDATE userdevicedetail SET userId = ` + userId + `,applicationId = ` + appId + `,deviceId = '` + userDevice.deviceId + `',fcmToken = '` + userDevice.fcmToken + `',deviceLocation = '` + userDevice.deviceLocation + `',deviceManufacturer = '` + userDevice.deviceManufacturer + `',deviceModel = '` + userDevice.deviceModel + `',apiCallTime = '` + userDevice.apiCallTime + `' WHERE userId = ` + userId;
                                                        result = await header.query(updateDetailSql);
                                                    } else {
                                                        let insertDetailSql = `INSERT INTO userdevicedetail(userId, applicationId, deviceId, fcmToken, deviceLocation, deviceManufacturer, deviceModel, apiCallTime) VALUES(` + userId + `,` + appId + `,'` + userDevice.deviceId + `','` + userDevice.fcmToken + `','` + userDevice.deviceLocation + `','` + userDevice.deviceManufacturer + `','` + userDevice.deviceModel + `','` + userDevice.apiCallTime + `')`;
                                                        result = await header.query(insertDetailSql);
                                                    }
                                                }
                                                let refreshToken = await createRefreshToken(userResult[0]);
                                                //insert refresh token
                                                let insertRefreshTokenSql = `INSERT INTO userrefreshtoken(userId, refreshToken, expireAt) VALUES(?,?,?)`;
                                                insertRefTokenResult = await header.query(insertRefreshTokenSql, [userResult[0].id, refreshToken.token, refreshToken.expireAt]);
                                                if (insertRefTokenResult && insertRefTokenResult.affectedRows > 0) {
                                                    userResult[0].refreshToken = refreshToken.token;

                                                    let userflagvalues = `SELECT ufv.*, uf.flagName, uf.displayName FROM userflagvalues ufv
                                                LEFT JOIN userflags uf ON uf.id = ufv.userFlagId
                                                WHERE ufv.userId = ` + userId + ``;
                                                    userResult[0].userFlags = await header.query(userflagvalues);

                                                    let todayDate = new Date();
                                                    let date = new Date(todayDate).getFullYear() + "-" + ("0" + (new Date(todayDate).getMonth() + 1)).slice(-2) + "-" + ("0" + new Date(todayDate).getDate()).slice(-2) + "";

                                                    let userPackages = `SELECT up.*, p.name as packageName, td.id as timeDurationId, td.value, p.weightage FROM userpackage up
                                                    LEFT JOIN package p ON p.id = up.packageId
                                                    LEFT JOIN packageduration pd ON pd.id = up.packageDurationId
                                                    LEFT JOIN timeduration td ON td.id = pd.timeDurationId
                                                    WHERE up.userId = ` + userId + ` AND DATE(up.startDate) <= DATE(CURRENT_TIMESTAMP()) AND DATE(up.endDate) >= DATE(CURRENT_TIMESTAMP())
                                                    order by p.weightage DESC`;
                                                    let userPackage = await header.query(userPackages);
                                                    if (userPackage && userPackage.length > 0) {
                                                        for (let k = 0; k < userPackage.length; k++) {
                                                            let packageFacility = await header.query(`SELECT pf.*, pff.name FROM packagefacility pf
                                                            LEFT JOIN premiumfacility pff ON pff.id = pf.premiumFacilityId
                                                             WHERE pf.packageId = ` + userPackage[k].packageId);
                                                            userPackage[k].packageFacility = packageFacility;
                                                        }
                                                    }
                                                    userResult[0].userPackage = userPackage[0];

                                                    //     let minAge = await header.query(`SELECT min(DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0) as minAge
                                                    // FROM users u
                                                    // LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                                                    // LEFT JOIN userroles ur ON ur.userId = u.id
                                                    // WHERE ur.roleId = 2 AND u.id != ` + userResult[0].id + ` AND (upa.userId = u.id) 
                                                    // AND u.id NOT IN (select userBlockId from userblock where userId = ` + userResult[0].id + `)`);
                                                    //     let maxAge = await header.query(`SELECT max(DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0) as maxAge
                                                    // FROM users u
                                                    // LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                                                    // LEFT JOIN userroles ur ON ur.userId = u.id
                                                    // WHERE ur.roleId = 2 AND u.id != ` + userResult[0].id + ` AND (upa.userId = u.id) 
                                                    // AND u.id NOT IN (select userBlockId from userblock where userId = ` + userResult[0].id + `)`);

                                                    //     let ageList = [];
                                                    //     for (let i = 18; i <= 60; i++) {
                                                    //         ageList.push(i)
                                                    //     }
                                                    //     console.log(ageList)

                                                    // let cityName = await header.query(`select (cityName) FROM addresses where cityName is not null or cityName !='' group by cityName  having  cityName !=''`)

                                                    // let occupationSql = `SELECT * FROM occupation WHERE isActive = 1 AND isDelete = 0`;
                                                    // let occupationResult = await header.query(occupationSql);

                                                    // let educationSql = `SELECT * FROM education WHERE isActive = 1 AND isDelete = 0`;
                                                    // let educationResult = await header.query(educationSql);

                                                    // let maritalStatusSql = `SELECT * FROM maritalstatus WHERE isActive = 1 AND isDelete = 0`;
                                                    // let maritalStatusResult = await header.query(maritalStatusSql);

                                                    // let religionSql = `SELECT * FROM religion WHERE isActive = 1 AND isDelete = 0`;
                                                    // let religionResult = await header.query(religionSql);

                                                    // let communitySql = `SELECT * FROM community WHERE isActive = 1 AND isDelete = 0`;
                                                    // let communityResult = await header.query(communitySql);

                                                    // let subCommunitySql = `SELECT * FROM subcommunity WHERE isActive = 1 AND isDelete = 0`;
                                                    // let subCommunityResult = await header.query(subCommunitySql);

                                                    // let dietSql = `SELECT * FROM diet WHERE isActive = 1 AND isDelete = 0`;
                                                    // let dietResult = await header.query(dietSql);

                                                    // let heightSql = `SELECT * FROM height WHERE isActive = 1 AND isDelete = 0 order by name`;
                                                    // let heightResult = await header.query(heightSql);

                                                    // let annualIncomeSql = `SELECT * FROM annualincome WHERE isActive = 1 AND isDelete = 0`;
                                                    // let annualIncomeResult = await header.query(annualIncomeSql);

                                                    // let employmentTypeSql = `SELECT * FROM employmenttype WHERE isActive = 1 AND isDelete = 0`;
                                                    // let employmentTypeResult = await header.query(employmentTypeSql);

                                                    // let documentTypeSql = `SELECT * FROM documenttype WHERE isActive = 1 AND isDelete = 0`;
                                                    // let documentTypeResult = await header.query(documentTypeSql);

                                                    // userResult[0].masterEntryData = {
                                                    //     "occupation": occupationResult,
                                                    //     "education": educationResult,
                                                    //     "maritalStatus": maritalStatusResult,
                                                    //     "religion": religionResult,
                                                    //     "community": communityResult,
                                                    //     "subCommunity": subCommunityResult,
                                                    //     "diet": dietResult,
                                                    //     "height": heightResult,
                                                    //     "annualIncome": annualIncomeResult,
                                                    //     "employmentType": employmentTypeResult,
                                                    //     "maxAge": maxAge[0].maxAge,
                                                    //     "minAge": minAge[0].minAge,
                                                    //     "ageList": ageList,
                                                    //     "cityName": cityName,
                                                    //     "documentType": documentTypeResult
                                                    // }


                                                    userResult[0].isVerified = false;
                                                    let isVerified = true;
                                                    let documentsSql = `SELECT ud.*, dt.name as documentTypeName FROM userdocument ud INNER JOIN documenttype dt ON dt.id = ud.documentTypeId WHERE userId = ` + userResult[0].id;
                                                    let documentsResult = await header.query(documentsSql);
                                                    userResult[0].userDocuments = documentsResult;
                                                    if (documentsResult && documentsResult.length > 0) {
                                                        for (let j = 0; j < documentsResult.length; j++) {
                                                            if (documentsResult[j].isRequired && !documentsResult[j].isVerified) {
                                                                isVerified = false;
                                                            }
                                                        }
                                                    } else {
                                                        isVerified = false;
                                                    }
                                                    userResult[0].isVerifiedProfile = isVerified;
                                                    userResult[0].isOAuth = false;
                                                    userResult[0].isAppleLogin = false;

                                                    userResult[0].userWalletAmount = 0;
                                                    let getUserWalletSql = `SELECT * FROM userwallets WHERE userId = ` + userResult[0].id;
                                                    let getUserWalletResult = await header.query(getUserWalletSql);
                                                    if (getUserWalletResult && getUserWalletResult.length > 0) {
                                                        userResult[0].userWalletAmount = getUserWalletResult[0].amount
                                                    }

                                                    await header.commit();
                                                    let successResult = new ResultSuccess(200, true, 'Login User', userResult, 1, "");
                                                    return res.status(200).send(successResult);
                                                } else {
                                                    await header.rollback();
                                                    let errorResult = new ResultError(400, true, "users.signUp() Error", new Error('Error While Login'), '');
                                                    next(errorResult);
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
                            }

                        }
                    } else {
                        let successResult = new ResultSuccess(200, true, 'Email is incorrect!', [], 1, "");
                        let isnum = /^\d+$/.test(req.body.email);
                        if (isnum) {
                            successResult = new ResultSuccess(200, true, 'Please enter mobile no. with country code', [], 1, "");
                        } else {
                            if (req.body.email.includes("+")) {
                                successResult = new ResultSuccess(200, true, 'Moble no. is incorrect!', [], 1, "");
                            }
                        }
                        return res.status(200).send(successResult);
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
        }
    } catch (error: any) {
        await header.rollback();
        let errorResult = new ResultError(500, true, 'Users.login() Exception', error, '');
        next(errorResult);
    }
};

const checkContactNoExist = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Check ContactNo Exist');
        let requiredFields = ['contactNo'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let userDevice = authorizationResult.currentUserDevice;
                let appId: number;
                if (userDevice.app == 'MatrimonyAdmin') {
                    appId = 1;
                } else if (userDevice.app == 'MatrimonyAndroid') {
                    appId = 2;
                } else {
                    appId = 3;
                }
                await header.beginTransaction();
                let userId: number;
                let insertRefTokenResult;
                let sql = `SELECT u.*, ur.roleId, img.imageUrl FROM users u
                        LEFT JOIN userroles ur ON ur.userId = u.id
                        LEFT JOIN images img ON img.id =u.imageId
                        WHERE u.contactNo = '` + req.body.contactNo + `' AND u.isActive = true AND ur.roleId = 2`;
                let result = await header.query(sql);
                if (result && result.length > 0) {
                    let userPerDetailSql = `SELECT u.id, u.firstName, u.middleName, u.lastName, u.gender, u.email, u.contactNo
                    , upd.birthDate, upd.languages, upd.eyeColor, upd.expectation, upd.weight, upd.profileForId, pf.name as profileForName
                    , upd.aboutMe, img.imageUrl, r.name as religion, ms.name as maritalStatus, c.name as community, o.name as occupation, e.name as education, sc.name as subCommunity
                    , ai.value as annualIncome, d.name as diet, h.name as height
                    , addr.addressLine1, addr.addressLine2, addr.pincode, addr.cityId, addr.districtId, addr.stateId, addr.countryId
                    , cit.name as cityName, ds.name as districtName, st.name as stateName, cou.name as countryName
                    , em.name as employmentType, DATE_FORMAT(FROM_DAYS(DATEDIFF(now(),upd.birthDate)), '%Y')+0 AS age
                    , addr.latitude, addr.longitude
                    FROM users u
                    LEFT JOIN userroles ur ON ur.userId = u.id
                    LEFT JOIN images img ON img.id = u.imageId
                    LEFT JOIN userpersonaldetail upd ON upd.userId = u.id
                    LEFT JOIN religion r ON r.id = upd.religionId
                    LEFT JOIN maritalstatus ms ON ms.id = upd.maritalStatusId
                    LEFT JOIN community c ON c.id = upd.communityId
                    LEFT JOIN occupation o ON o.id = upd.occupationId
                    LEFT JOIN education e ON e.id = upd.educationId
                    LEFT JOIN subcommunity sc ON sc.id = upd.subCommunityId
                    LEFT JOIN annualincome ai ON ai.id = upd.annualIncomeId
                    LEFT JOIN diet d ON d.id = upd.dietId
                    LEFT JOIN height h ON h.id = upd.heightId
                    LEFT JOIN addresses addr ON addr.id = upd.addressId
                    LEFT JOIN cities cit ON addr.cityId = cit.id
                    LEFT JOIN districts ds ON addr.districtId = ds.id
                    LEFT JOIN state st ON addr.stateId = st.id
                    LEFT JOIN countries cou ON addr.countryId = cou.id
                    LEFT JOIN employmenttype em ON em.id = upd.employmenttypeId
                    LEFT JOIN profilefor pf ON pf.id = upd.profileForId
                     WHERE ur.roleId = 2
                      AND u.contactNo =  '` + req.body.contactNo + `' `;
                    let userResult = await header.query(userPerDetailSql);
                    if (userResult && userResult.length > 0) {
                        let checkbloclsql = `SELECT * FROM userblockrequest WHERE blockRequestUserId = ` + result[0].id;
                        let checkbloclResult = await header.query(checkbloclsql);
                        if (checkbloclResult && checkbloclResult.length > 0) {
                            let successResult = new ResultSuccess(401, true, 'Your account was bloacked', [], 1, "");
                            return res.status(200).send(successResult);
                        } else {
                            if (result[0].isDisable) {
                                let errorResult = new ResultError(400, true, "users.login() Error", new Error('Your profile was block by Admin. You cannot login.'), '');
                                next(errorResult);
                            } else {
                                userId = result[0].id;
                                if (result && result.length > 0) {
                                    //bcryptjs.compare(req.body.password, result[0].password, async (error, hashresult: any) => {
                                    // if (hashresult == false) {
                                    //     return res.status(401).json({
                                    //         message: 'Password Mismatch'
                                    //     });
                                    // } else if (hashresult) {
                                    let signJWTResult: any = await signJWT(result[0]);
                                    if (signJWTResult && signJWTResult.token) {
                                        userResult[0].token = signJWTResult.token;
                                        if (userDevice) {
                                            let checkDeviceSql = `SELECT * FROM userdevicedetail WHERE userId = ` + userId + ``;
                                            result = await header.query(checkDeviceSql);
                                            userDevice.apiCallTime = userDevice.apiCallTime ? userDevice.apiCallTime : '';
                                            if (result && result.length > 0) {
                                                let updateDetailSql = `UPDATE userdevicedetail SET userId = ` + userId + `,applicationId = ` + appId + `,deviceId = '` + userDevice.deviceId + `',fcmToken = '` + userDevice.fcmToken + `',deviceLocation = '` + userDevice.deviceLocation + `',deviceManufacturer = '` + userDevice.deviceManufacturer + `',deviceModel = '` + userDevice.deviceModel + `',apiCallTime = '` + userDevice.apiCallTime + `' WHERE userId = ` + userId;
                                                result = await header.query(updateDetailSql);
                                            } else {
                                                let insertDetailSql = `INSERT INTO userdevicedetail(userId, applicationId, deviceId, fcmToken, deviceLocation, deviceManufacturer, deviceModel, apiCallTime) VALUES(` + userId + `,` + appId + `,'` + userDevice.deviceId + `','` + userDevice.fcmToken + `','` + userDevice.deviceLocation + `','` + userDevice.deviceManufacturer + `','` + userDevice.deviceModel + `','` + userDevice.apiCallTime + `')`;
                                                result = await header.query(insertDetailSql);
                                            }
                                        }
                                        let refreshToken = await createRefreshToken(userResult[0]);
                                        //insert refresh token
                                        let insertRefreshTokenSql = `INSERT INTO userrefreshtoken(userId, refreshToken, expireAt) VALUES(?,?,?)`;
                                        insertRefTokenResult = await header.query(insertRefreshTokenSql, [userResult[0].id, refreshToken.token, refreshToken.expireAt]);
                                        if (insertRefTokenResult && insertRefTokenResult.affectedRows > 0) {
                                            userResult[0].refreshToken = refreshToken.token;

                                            let userflagvalues = `SELECT ufv.*, uf.flagName, uf.displayName FROM userflagvalues ufv
                                                LEFT JOIN userflags uf ON uf.id = ufv.userFlagId
                                                WHERE ufv.userId = ` + userId + ``;
                                            userResult[0].userFlags = await header.query(userflagvalues);

                                            let todayDate = new Date();
                                            let date = new Date(todayDate).getFullYear() + "-" + ("0" + (new Date(todayDate).getMonth() + 1)).slice(-2) + "-" + ("0" + new Date(todayDate).getDate()).slice(-2) + "";

                                            let userPackages = `SELECT up.*, p.name as packageName, td.id as timeDurationId, td.value, p.weightage FROM userpackage up
                                                    LEFT JOIN package p ON p.id = up.packageId
                                                    LEFT JOIN packageduration pd ON pd.id = up.packageDurationId
                                                    LEFT JOIN timeduration td ON td.id = pd.timeDurationId
                                                        WHERE up.userId = ` + userId + ` AND DATE(up.startDate) <= DATE(CURRENT_TIMESTAMP()) AND DATE(up.endDate) >= DATE(CURRENT_TIMESTAMP())
                                                        order by p.weightage DESC`;
                                            let userPackage = await header.query(userPackages);
                                            if (userPackage && userPackage.length > 0) {
                                                for (let k = 0; k < userPackage.length; k++) {
                                                    let packageFacility = await header.query(`SELECT pf.*, pff.name FROM packagefacility pf
                                                            LEFT JOIN premiumfacility pff ON pff.id = pf.premiumFacilityId
                                                             WHERE pf.packageId = ` + userPackage[k].packageId);
                                                    userPackage[k].packageFacility = packageFacility;
                                                }
                                            }
                                            userResult[0].userPackage = userPackage[0];

                                            // let minAge = await header.query(`SELECT min(DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0) as minAge
                                            //     FROM users u
                                            //     LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                                            //     LEFT JOIN userroles ur ON ur.userId = u.id
                                            //     WHERE ur.roleId = 2 AND u.id != ` + userResult[0].id + ` AND (upa.userId = u.id) 
                                            //     AND u.id NOT IN (select userBlockId from userblock where userId = ` + userResult[0].id + `)`);
                                            // let maxAge = await header.query(`SELECT max(DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0) as maxAge
                                            //     FROM users u
                                            //     LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                                            //     LEFT JOIN userroles ur ON ur.userId = u.id
                                            //     WHERE ur.roleId = 2 AND u.id != ` + userResult[0].id + ` AND (upa.userId = u.id) 
                                            //     AND u.id NOT IN (select userBlockId from userblock where userId = ` + userResult[0].id + `)`);

                                            // let ageList = [];
                                            // for (let i = 18; i <= 60; i++) {
                                            //     ageList.push(i)
                                            // }
                                            // console.log(ageList)

                                            // let cityName = await header.query(`select (cityName) FROM addresses where cityName is not null or cityName !='' group by cityName  having  cityName !=''`)

                                            // let occupationSql = `SELECT * FROM occupation WHERE isActive = 1 AND isDelete = 0`;
                                            // let occupationResult = await header.query(occupationSql);

                                            // let educationSql = `SELECT * FROM education WHERE isActive = 1 AND isDelete = 0`;
                                            // let educationResult = await header.query(educationSql);

                                            // let maritalStatusSql = `SELECT * FROM maritalstatus WHERE isActive = 1 AND isDelete = 0`;
                                            // let maritalStatusResult = await header.query(maritalStatusSql);

                                            // let religionSql = `SELECT * FROM religion WHERE isActive = 1 AND isDelete = 0`;
                                            // let religionResult = await header.query(religionSql);

                                            // let communitySql = `SELECT * FROM community WHERE isActive = 1 AND isDelete = 0`;
                                            // let communityResult = await header.query(communitySql);

                                            // let subCommunitySql = `SELECT * FROM subcommunity WHERE isActive = 1 AND isDelete = 0`;
                                            // let subCommunityResult = await header.query(subCommunitySql);

                                            // let dietSql = `SELECT * FROM diet WHERE isActive = 1 AND isDelete = 0`;
                                            // let dietResult = await header.query(dietSql);

                                            // let heightSql = `SELECT * FROM height WHERE isActive = 1 AND isDelete = 0 order by name`;
                                            // let heightResult = await header.query(heightSql);

                                            // let annualIncomeSql = `SELECT * FROM annualincome WHERE isActive = 1 AND isDelete = 0`;
                                            // let annualIncomeResult = await header.query(annualIncomeSql);

                                            // let employmentTypeSql = `SELECT * FROM employmenttype WHERE isActive = 1 AND isDelete = 0`;
                                            // let employmentTypeResult = await header.query(employmentTypeSql);

                                            // let documentTypeSql = `SELECT * FROM documenttype WHERE isActive = 1 AND isDelete = 0`;
                                            // let documentTypeResult = await header.query(documentTypeSql);

                                            // userResult[0].masterEntryData = {
                                            //     "occupation": occupationResult,
                                            //     "education": educationResult,
                                            //     "maritalStatus": maritalStatusResult,
                                            //     "religion": religionResult,
                                            //     "community": communityResult,
                                            //     "subCommunity": subCommunityResult,
                                            //     "diet": dietResult,
                                            //     "height": heightResult,
                                            //     "annualIncome": annualIncomeResult,
                                            //     "employmentType": employmentTypeResult,
                                            //     "maxAge": maxAge[0].maxAge,
                                            //     "minAge": minAge[0].minAge,
                                            //     "ageList": ageList,
                                            //     "cityName": cityName,
                                            //     "documentType": documentTypeResult
                                            // }

                                            userResult[0].isVerified = false;
                                            let isVerified = true;
                                            let documentsSql = `SELECT ud.*, dt.name as documentTypeName FROM userdocument ud INNER JOIN documenttype dt ON dt.id = ud.documentTypeId WHERE userId = ` + userResult[0].id;
                                            let documentsResult = await header.query(documentsSql);
                                            userResult[0].userDocuments = documentsResult;
                                            if (documentsResult && documentsResult.length > 0) {
                                                for (let j = 0; j < documentsResult.length; j++) {
                                                    if (documentsResult[j].isRequired && !documentsResult[j].isVerified) {
                                                        isVerified = false;
                                                    }
                                                }
                                            } else {
                                                isVerified = false;
                                            }
                                            userResult[0].isVerifiedProfile = isVerified;
                                            userResult[0].isOAuth = false;
                                            userResult[0].isAppleLogin = false;

                                            userResult[0].userWalletAmount = 0;
                                            let getUserWalletSql = `SELECT * FROM userwallets WHERE userId = ` + userResult[0].id;
                                            let getUserWalletResult = await header.query(getUserWalletSql);
                                            if (getUserWalletResult && getUserWalletResult.length > 0) {
                                                userResult[0].userWalletAmount = getUserWalletResult[0].amount
                                            }

                                            await header.commit();
                                            let successResult = new ResultSuccess(200, true, 'Login User', userResult, 1, "");
                                            return res.status(200).send(successResult);
                                        } else {
                                            await header.rollback();
                                            let errorResult = new ResultError(400, true, "users.signUp() Error", new Error('Error While Login'), '');
                                            next(errorResult);
                                        }
                                    } else {
                                        return res.status(401).json({
                                            message: 'Unable to Sign JWT',
                                            error: signJWTResult.error
                                        });
                                    }
                                    // }
                                    //});
                                } else {
                                    await header.rollback();
                                    let errorResult = new ResultError(400, true, "users.login() Error", new Error('Error While Login'), '');
                                    next(errorResult);
                                }
                            }

                        }
                    } else {
                        // let errorResult = new ResultError(203, true, "User Not Available", new Error("User Not Available"), '');
                        // next(errorResult);
                        let userDevice = authorizationResult.currentUserDevice;
                        let appId: number;
                        if (userDevice.app == 'MatrimonyAdmin') {
                            appId = 1;
                        } else if (userDevice.app == 'MatrimonyAndroid') {
                            appId = 2;
                        } else {
                            appId = 3;
                        }
                        req.body.imageId = req.body.imageId ? req.body.imageId : null;
                        await header.beginTransaction();
                        if (req.body.email) {
                            let checkEmail = `SELECT * FROM users WHERE email = '` + req.body.email + `'`;
                            let checkEmailResult = await header.query(checkEmail);
                            if (checkEmailResult && checkEmailResult.length > 0) {
                                await header.rollback();
                                let successResult = 'Email Already Inserted';
                                return res.status(200).send(successResult);
                            } else {
                                let sql = `INSERT INTO users(contactNo, email, isDisable) VALUES ('` + req.body.contactNo + `','` + req.body.email + `', 0)`;
                                let result = await header.query(sql);
                                if (result && result.insertId > 0) {
                                    let userId = result.insertId;
                                    let userRoleSql = `INSERT INTO userroles(userId, roleId) VALUES (` + userId + `, 2) `;
                                    result = await header.query(userRoleSql);
                                    if (result && result.affectedRows > 0) {
                                        if (userDevice) {
                                            userDevice.apiCallTime = userDevice.apiCallTime ? userDevice.apiCallTime : '';
                                            let deviceDetailSql = `INSERT INTO userdevicedetail(userId, applicationId, deviceId, fcmToken, deviceLocation, deviceManufacturer, deviceModel, apiCallTime) VALUES(` + userId + `,` + appId + `,'` + userDevice.deviceId + `','` + userDevice.fcmToken + `','` + userDevice.deviceLocation + `','` + userDevice.deviceManufacturer + `','` + userDevice.deviceModel + `','` + userDevice.apiCallTime + `')`;
                                            let deviceDetailResult = await header.query(deviceDetailSql);
                                        }
                                        let userFlag = await header.query(`SELECT * FROM userflags`);
                                        if (userFlag && userFlag.length > 0) {
                                            for (let index = 0; index < userFlag.length; index++) {
                                                let userFlagSql = `INSERT INTO userflagvalues(userId, userFlagId, userFlagValue) VALUES (` + userId + `, ` + userFlag[index].id + `, ` + userFlag[index].defaultValue + `)`
                                                let userFlagSqlResult = await header.query(userFlagSql);
                                            }
                                        }
                                        let userPerDetailSql = `SELECT u.id, u.firstName, u.middleName, u.lastName, u.gender, u.email, u.contactNo
                                        , upd.birthDate, upd.languages, upd.eyeColor, upd.expectation, upd.aboutMe, upd.weight, upd.profileForId, pf.name as profileForName
                                        , img.imageUrl, r.name as religion, ms.name as maritalStatus, c.name as community, o.name as occupation, e.name as education, sc.name as subCommunity, ai.value as annualIncome, d.name as diet, h.name as height
                                    , addr.addressLine1, addr.addressLine2, addr.pincode, addr.cityId, addr.districtId, addr.stateId, addr.countryId
                                    , cit.name as cityName, ds.name as districtName, st.name as stateName, cou.name as countryName
                                    , em.name as employmentType, DATE_FORMAT(FROM_DAYS(DATEDIFF(now(),upd.birthDate)), '%Y')+0 AS age
                                    , addr.latitude, addr.longitude
                                FROM users u
                                LEFT JOIN userroles ur ON ur.userId = u.id
                                LEFT JOIN images img ON img.id = u.imageId
                                LEFT JOIN userpersonaldetail upd ON upd.userId = u.id
                                LEFT JOIN religion r ON r.id = upd.religionId
                                LEFT JOIN maritalstatus ms ON ms.id = upd.maritalStatusId
                                LEFT JOIN community c ON c.id = upd.communityId
                                LEFT JOIN occupation o ON o.id = upd.occupationId
                                LEFT JOIN education e ON e.id = upd.educationId
                                LEFT JOIN subcommunity sc ON sc.id = upd.subCommunityId
                                LEFT JOIN annualincome ai ON ai.id = upd.annualIncomeId
                                LEFT JOIN diet d ON d.id = upd.dietId
                                LEFT JOIN height h ON h.id = upd.heightId
                                LEFT JOIN addresses addr ON addr.id = upd.addressId
                                LEFT JOIN cities cit ON addr.cityId = cit.id
                                LEFT JOIN districts ds ON addr.districtId = ds.id
                                LEFT JOIN state st ON addr.stateId = st.id
                                LEFT JOIN countries cou ON addr.countryId = cou.id
                                LEFT JOIN employmenttype em ON em.id = upd.employmenttypeId
                                LEFT JOIN profilefor pf ON pf.id = upd.profileForId
                                 WHERE ur.roleId = 2 AND u.id =  ` + userId + ``;
                                        let userResult: any = await header.query(userPerDetailSql);
                                        let signJWTResult: any = await signJWT(userResult[0]);
                                        if (signJWTResult && signJWTResult.token) {
                                            userResult[0].token = signJWTResult.token;
                                            let refreshToken = await createRefreshToken(userResult[0]);
                                            //insert refresh token
                                            let insertRefreshTokenSql = `INSERT INTO userrefreshtoken(userId, refreshToken, expireAt) VALUES(?,?,?)`;
                                            insertRefTokenResult = await header.query(insertRefreshTokenSql, [userResult[0].id, refreshToken.token, refreshToken.expireAt]);
                                            if (insertRefTokenResult && insertRefTokenResult.affectedRows > 0) {
                                                userResult[0].refreshToken = refreshToken.token;

                                                let userflagvalues = `SELECT ufv.*, uf.flagName, uf.displayName FROM userflagvalues ufv
                                        LEFT JOIN userflags uf ON uf.id = ufv.userFlagId
                                        WHERE ufv.userId = ` + userId + ``;
                                                userResult[0].userFlags = await header.query(userflagvalues);

                                                let todayDate = new Date();
                                                let date = new Date(todayDate).getFullYear() + "-" + ("0" + (new Date(todayDate).getMonth() + 1)).slice(-2) + "-" + ("0" + new Date(todayDate).getDate()).slice(-2) + "";

                                                let userPackages = `SELECT up.*, p.name as packageName, td.id as timeDurationId, td.value FROM userpackage up
                                        LEFT JOIN package p ON p.id = up.packageId
                                        LEFT JOIN packageduration pd ON pd.id = up.packageDurationId
                                        LEFT JOIN timeduration td ON td.id = pd.timeDurationId
                                            WHERE up.userId = ` + userId + ` order by createdDate DESC`;
                                                let userPackage = await header.query(userPackages);
                                                if (userPackage && userPackage.length > 0) {
                                                    for (let k = 0; k < userPackage.length; k++) {
                                                        let packageFacility = await header.query(`SELECT pf.*, pff.name FROM packagefacility pf
                                                LEFT JOIN premiumfacility pff ON pff.id = pf.premiumFacilityId
                                                 WHERE pf.packageId = ` + userPackage[k].packageId);
                                                        userPackage[k].packageFacility = packageFacility;
                                                    }
                                                }
                                                userResult[0].userPackage = userPackage[0];

                                                //     let minAge = await header.query(`SELECT min(DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0) as minAge
                                                // FROM users u
                                                // LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                                                // LEFT JOIN userroles ur ON ur.userId = u.id
                                                // WHERE ur.roleId = 2 AND u.id != ` + userResult[0].id + ` AND (upa.userId = u.id) AND u.id NOT IN (select userBlockId from userblock where userId = ` + userResult[0].id + `)`);
                                                //     let maxAge = await header.query(`SELECT max(DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0) as maxAge
                                                // FROM users u
                                                // LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                                                // LEFT JOIN userroles ur ON ur.userId = u.id
                                                // WHERE ur.roleId = 2 AND u.id != ` + userResult[0].id + ` AND (upa.userId = u.id) AND u.id NOT IN (select userBlockId from userblock where userId = ` + userResult[0].id + `)`);

                                                //     let occupationSql = `SELECT * FROM occupation WHERE isActive = 1 AND isDelete = 0`;
                                                //     let occupationResult = await header.query(occupationSql);

                                                //     let educationSql = `SELECT * FROM education WHERE isActive = 1 AND isDelete = 0`;
                                                //     let educationResult = await header.query(educationSql);

                                                //     let maritalStatusSql = `SELECT * FROM maritalstatus WHERE isActive = 1 AND isDelete = 0`;
                                                //     let maritalStatusResult = await header.query(maritalStatusSql);

                                                //     let religionSql = `SELECT * FROM religion WHERE isActive = 1 AND isDelete = 0`;
                                                //     let religionResult = await header.query(religionSql);

                                                //     let communitySql = `SELECT * FROM community WHERE isActive = 1 AND isDelete = 0`;
                                                //     let communityResult = await header.query(communitySql);

                                                //     let subCommunitySql = `SELECT * FROM subcommunity WHERE isActive = 1 AND isDelete = 0`;
                                                //     let subCommunityResult = await header.query(subCommunitySql);

                                                //     let dietSql = `SELECT * FROM diet WHERE isActive = 1 AND isDelete = 0`;
                                                //     let dietResult = await header.query(dietSql);

                                                //     let heightSql = `SELECT * FROM height WHERE isActive = 1 AND isDelete = 0 order by name`;
                                                //     let heightResult = await header.query(heightSql);

                                                //     let annualIncomeSql = `SELECT * FROM annualincome WHERE isActive = 1 AND isDelete = 0`;
                                                //     let annualIncomeResult = await header.query(annualIncomeSql);

                                                //     let employmentTypeSql = `SELECT * FROM employmenttype WHERE isActive = 1 AND isDelete = 0`;
                                                //     let employmentTypeResult = await header.query(employmentTypeSql);

                                                //     let documentTypeSql = `SELECT * FROM documenttype WHERE isActive = 1 AND isDelete = 0`;
                                                //     let documentTypeResult = await header.query(documentTypeSql);

                                                //     userResult[0].masterEntryData = {
                                                //         "occupation": occupationResult,
                                                //         "education": educationResult,
                                                //         "maritalStatus": maritalStatusResult,
                                                //         "religion": religionResult,
                                                //         "community": communityResult,
                                                //         "subCommunity": subCommunityResult,
                                                //         "diet": dietResult,
                                                //         "height": heightResult,
                                                //         "annualIncome": annualIncomeResult,
                                                //         "employmentType": employmentTypeResult,
                                                //         "maxAge": maxAge[0].maxAge,
                                                //         "minAge": minAge[0].minAge,
                                                //         "documentType": documentTypeResult
                                                //     }

                                                userResult[0].isVerified = false;
                                                let isVerified = true;
                                                let documentsSql = `SELECT ud.*, dt.name as documentTypeName FROM userdocument ud INNER JOIN documenttype dt ON dt.id = ud.documentTypeId WHERE userId = ` + userResult[0].id;
                                                let documentsResult = await header.query(documentsSql);
                                                userResult[0].userDocuments = documentsResult;
                                                if (documentsResult && documentsResult.length > 0) {
                                                    for (let j = 0; j < documentsResult.length; j++) {
                                                        if (documentsResult[j].isRequired && !documentsResult[j].isVerified) {
                                                            isVerified = false;
                                                        }
                                                    }
                                                } else {
                                                    isVerified = false;
                                                }
                                                userResult[0].isVerifiedProfile = isVerified;
                                                userResult[0].isOAuth = false;
                                                userResult[0].isAppleLogin = false;

                                                userResult[0].userWalletAmount = 0;
                                                let getUserWalletSql = `SELECT * FROM userwallets WHERE userId = ` + userResult[0].id;
                                                let getUserWalletResult = await header.query(getUserWalletSql);
                                                if (getUserWalletResult && getUserWalletResult.length > 0) {
                                                    userResult[0].userWalletAmount = getUserWalletResult[0].amount
                                                }

                                                await header.commit();
                                                //Note: Return 203 Status because in app need to complete profile screen
                                                let successResult = new ResultSuccess(203, true, 'Login User', userResult, 1, "");
                                                return res.status(203).send(successResult);
                                            } else {
                                                await header.rollback();
                                                let errorResult = new ResultError(400, true, "users.signUp() Error", new Error('Error While Login'), '');
                                                next(errorResult);
                                            }
                                        } else {
                                            await header.rollback();
                                            return res.status(401).json({
                                                message: 'Unable to Sign JWT',
                                                error: signJWTResult.error
                                            });
                                        }
                                    } else {
                                        await header.rollback();
                                        let errorResult = new ResultError(400, true, "users.signUp() Error", new Error('Error While Inserting Data'), '');
                                        next(errorResult);
                                    }
                                } else {
                                    await header.rollback();
                                    let errorResult = new ResultError(400, true, "users.signUp() Error", new Error('Error While Inserting Data'), '');
                                    next(errorResult);
                                }
                            }
                        } else {
                            let checkEmail = `SELECT * FROM users WHERE contactNo = '` + req.body.contactNo + `'`;
                            let checkEmailResult = await header.query(checkEmail);
                            if (checkEmailResult && checkEmailResult.length > 0) {
                                await header.rollback();
                                let successResult = 'Contact No Already Inserted';
                                return res.status(200).send(successResult);
                            } else {
                                let sql = `INSERT INTO users(contactNo, isDisable, referalUserId) VALUES ('` + req.body.contactNo + `', 0,` + (req.body.referalUserId ? req.body.referalUserId : null) + `)`;
                                let result = await header.query(sql);
                                if (result && result.insertId > 0) {
                                    let userId = result.insertId;
                                    let userRoleSql = `INSERT INTO userroles(userId, roleId) VALUES (` + userId + `, 2) `;
                                    result = await header.query(userRoleSql);
                                    if (result && result.affectedRows > 0) {
                                        if (userDevice) {
                                            userDevice.apiCallTime = userDevice.apiCallTime ? userDevice.apiCallTime : '';
                                            let deviceDetailSql = `INSERT INTO userdevicedetail(userId, applicationId, deviceId, fcmToken, deviceLocation, deviceManufacturer, deviceModel, apiCallTime) VALUES(` + userId + `,` + appId + `,'` + userDevice.deviceId + `','` + userDevice.fcmToken + `','` + userDevice.deviceLocation + `','` + userDevice.deviceManufacturer + `','` + userDevice.deviceModel + `','` + userDevice.apiCallTime + `')`;
                                            let deviceDetailResult = await header.query(deviceDetailSql);
                                        }
                                        let userFlag = await header.query(`SELECT * FROM userflags`);
                                        if (userFlag && userFlag.length > 0) {
                                            for (let index = 0; index < userFlag.length; index++) {
                                                let userFlagSql = `INSERT INTO userflagvalues(userId, userFlagId, userFlagValue) VALUES (` + userId + `, ` + userFlag[index].id + `, ` + userFlag[index].defaultValue + `)`
                                                let userFlagSqlResult = await header.query(userFlagSql);
                                            }
                                        }
                                        let userPerDetailSql = `SELECT u.id, u.firstName, u.middleName, u.lastName, u.gender, u.email, u.contactNo
                                        , upd.birthDate, upd.languages, upd.eyeColor, upd.expectation, upd.aboutMe, upd.weight, upd.profileForId, pf.name as profileForName
                                        , img.imageUrl, r.name as religion, ms.name as maritalStatus, c.name as community, o.name as occupation, e.name as education, sc.name as subCommunity, ai.value as annualIncome, d.name as diet, h.name as height
                                    , addr.addressLine1, addr.addressLine2, addr.pincode, addr.cityId, addr.districtId, addr.stateId, addr.countryId
                                    , cit.name as cityName, ds.name as districtName, st.name as stateName, cou.name as countryName
                                    , em.name as employmentType, DATE_FORMAT(FROM_DAYS(DATEDIFF(now(),upd.birthDate)), '%Y')+0 AS age
                                    , addr.latitude, addr.longitude
                                FROM users u
                                LEFT JOIN userroles ur ON ur.userId = u.id
                                LEFT JOIN images img ON img.id = u.imageId
                                LEFT JOIN userpersonaldetail upd ON upd.userId = u.id
                                LEFT JOIN religion r ON r.id = upd.religionId
                                LEFT JOIN maritalstatus ms ON ms.id = upd.maritalStatusId
                                LEFT JOIN community c ON c.id = upd.communityId
                                LEFT JOIN occupation o ON o.id = upd.occupationId
                                LEFT JOIN education e ON e.id = upd.educationId
                                LEFT JOIN subcommunity sc ON sc.id = upd.subCommunityId
                                LEFT JOIN annualincome ai ON ai.id = upd.annualIncomeId
                                LEFT JOIN diet d ON d.id = upd.dietId
                                LEFT JOIN height h ON h.id = upd.heightId
                                LEFT JOIN addresses addr ON addr.id = upd.addressId
                                LEFT JOIN cities cit ON addr.cityId = cit.id
                                LEFT JOIN districts ds ON addr.districtId = ds.id
                                LEFT JOIN state st ON addr.stateId = st.id
                                LEFT JOIN countries cou ON addr.countryId = cou.id
                                LEFT JOIN employmenttype em ON em.id = upd.employmenttypeId
                                LEFT JOIN profilefor pf ON pf.id = upd.profileForId
                                 WHERE ur.roleId = 2 AND u.id =  ` + userId + ``;
                                        let userResult: any = await header.query(userPerDetailSql);
                                        let signJWTResult: any = await signJWT(userResult[0]);
                                        if (signJWTResult && signJWTResult.token) {
                                            userResult[0].token = signJWTResult.token;
                                            let refreshToken = await createRefreshToken(userResult[0]);
                                            //insert refresh token
                                            let insertRefreshTokenSql = `INSERT INTO userrefreshtoken(userId, refreshToken, expireAt) VALUES(?,?,?)`;
                                            insertRefTokenResult = await header.query(insertRefreshTokenSql, [userResult[0].id, refreshToken.token, refreshToken.expireAt]);
                                            if (insertRefTokenResult && insertRefTokenResult.affectedRows > 0) {
                                                userResult[0].refreshToken = refreshToken.token;

                                                let userflagvalues = `SELECT ufv.*, uf.flagName, uf.displayName FROM userflagvalues ufv
                                        LEFT JOIN userflags uf ON uf.id = ufv.userFlagId
                                        WHERE ufv.userId = ` + userId + ``;
                                                userResult[0].userFlags = await header.query(userflagvalues);

                                                let todayDate = new Date();
                                                let date = new Date(todayDate).getFullYear() + "-" + ("0" + (new Date(todayDate).getMonth() + 1)).slice(-2) + "-" + ("0" + new Date(todayDate).getDate()).slice(-2) + "";

                                                let userPackages = `SELECT up.*, p.name as packageName, td.id as timeDurationId, td.value FROM userpackage up
                                        LEFT JOIN package p ON p.id = up.packageId
                                        LEFT JOIN packageduration pd ON pd.id = up.packageDurationId
                                        LEFT JOIN timeduration td ON td.id = pd.timeDurationId
                                            WHERE up.userId = ` + userId + ` order by createdDate DESC`;
                                                let userPackage = await header.query(userPackages);
                                                if (userPackage && userPackage.length > 0) {
                                                    for (let k = 0; k < userPackage.length; k++) {
                                                        let packageFacility = await header.query(`SELECT pf.*, pff.name FROM packagefacility pf
                                                LEFT JOIN premiumfacility pff ON pff.id = pf.premiumFacilityId
                                                 WHERE pf.packageId = ` + userPackage[k].packageId);
                                                        userPackage[k].packageFacility = packageFacility;
                                                    }
                                                }
                                                userResult[0].userPackage = userPackage[0];

                                                //     let minAge = await header.query(`SELECT min(DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0) as minAge
                                                // FROM users u
                                                // LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                                                // LEFT JOIN userroles ur ON ur.userId = u.id
                                                // WHERE ur.roleId = 2 AND u.id != ` + userResult[0].id + ` AND (upa.userId = u.id) AND u.id NOT IN (select userBlockId from userblock where userId = ` + userResult[0].id + `)`);
                                                //     let maxAge = await header.query(`SELECT max(DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0) as maxAge
                                                // FROM users u
                                                // LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                                                // LEFT JOIN userroles ur ON ur.userId = u.id
                                                // WHERE ur.roleId = 2 AND u.id != ` + userResult[0].id + ` AND (upa.userId = u.id) AND u.id NOT IN (select userBlockId from userblock where userId = ` + userResult[0].id + `)`);

                                                //     let occupationSql = `SELECT * FROM occupation WHERE isActive = 1 AND isDelete = 0`;
                                                //     let occupationResult = await header.query(occupationSql);

                                                //     let educationSql = `SELECT * FROM education WHERE isActive = 1 AND isDelete = 0`;
                                                //     let educationResult = await header.query(educationSql);

                                                //     let maritalStatusSql = `SELECT * FROM maritalstatus WHERE isActive = 1 AND isDelete = 0`;
                                                //     let maritalStatusResult = await header.query(maritalStatusSql);

                                                //     let religionSql = `SELECT * FROM religion WHERE isActive = 1 AND isDelete = 0`;
                                                //     let religionResult = await header.query(religionSql);

                                                //     let communitySql = `SELECT * FROM community WHERE isActive = 1 AND isDelete = 0`;
                                                //     let communityResult = await header.query(communitySql);

                                                //     let subCommunitySql = `SELECT * FROM subcommunity WHERE isActive = 1 AND isDelete = 0`;
                                                //     let subCommunityResult = await header.query(subCommunitySql);

                                                //     let dietSql = `SELECT * FROM diet WHERE isActive = 1 AND isDelete = 0`;
                                                //     let dietResult = await header.query(dietSql);

                                                //     let heightSql = `SELECT * FROM height WHERE isActive = 1 AND isDelete = 0 order by name`;
                                                //     let heightResult = await header.query(heightSql);

                                                //     let annualIncomeSql = `SELECT * FROM annualincome WHERE isActive = 1 AND isDelete = 0`;
                                                //     let annualIncomeResult = await header.query(annualIncomeSql);

                                                //     let employmentTypeSql = `SELECT * FROM employmenttype WHERE isActive = 1 AND isDelete = 0`;
                                                //     let employmentTypeResult = await header.query(employmentTypeSql);

                                                //     let documentTypeSql = `SELECT * FROM documenttype WHERE isActive = 1 AND isDelete = 0`;
                                                //     let documentTypeResult = await header.query(documentTypeSql);

                                                //     userResult[0].masterEntryData = {
                                                //         "occupation": occupationResult,
                                                //         "education": educationResult,
                                                //         "maritalStatus": maritalStatusResult,
                                                //         "religion": religionResult,
                                                //         "community": communityResult,
                                                //         "subCommunity": subCommunityResult,
                                                //         "diet": dietResult,
                                                //         "height": heightResult,
                                                //         "annualIncome": annualIncomeResult,
                                                //         "employmentType": employmentTypeResult,
                                                //         "maxAge": maxAge[0].maxAge,
                                                //         "minAge": minAge[0].minAge,
                                                //         "documentType": documentTypeResult
                                                //     }

                                                userResult[0].isVerified = false;
                                                let isVerified = true;
                                                let documentsSql = `SELECT ud.*, dt.name as documentTypeName FROM userdocument ud INNER JOIN documenttype dt ON dt.id = ud.documentTypeId WHERE userId = ` + userResult[0].id;
                                                let documentsResult = await header.query(documentsSql);
                                                userResult[0].userDocuments = documentsResult;
                                                if (documentsResult && documentsResult.length > 0) {
                                                    for (let j = 0; j < documentsResult.length; j++) {
                                                        if (documentsResult[j].isRequired && !documentsResult[j].isVerified) {
                                                            isVerified = false;
                                                        }
                                                    }
                                                } else {
                                                    isVerified = false;
                                                }
                                                userResult[0].isVerifiedProfile = isVerified;
                                                userResult[0].isOAuth = false;
                                                userResult[0].isAppleLogin = false;

                                                userResult[0].userWalletAmount = 0;
                                                let getUserWalletSql = `SELECT * FROM userwallets WHERE userId = ` + userResult[0].id;
                                                let getUserWalletResult = await header.query(getUserWalletSql);
                                                if (getUserWalletResult && getUserWalletResult.length > 0) {
                                                    userResult[0].userWalletAmount = getUserWalletResult[0].amount
                                                }

                                                await header.commit();
                                                //Note: Return 203 Status because in app need to complete profile screen
                                                let successResult = new ResultSuccess(203, true, 'Login User', userResult, 1, "");
                                                return res.status(203).send(successResult);
                                            } else {
                                                await header.rollback();
                                                let errorResult = new ResultError(400, true, "users.signUp() Error", new Error('Error While Login'), '');
                                                next(errorResult);
                                            }
                                        } else {
                                            await header.rollback();
                                            return res.status(401).json({
                                                message: 'Unable to Sign JWT',
                                                error: signJWTResult.error
                                            });
                                        }
                                    } else {
                                        await header.rollback();
                                        let errorResult = new ResultError(400, true, "users.signUp() Error", new Error('Error While Inserting Data'), '');
                                        next(errorResult);
                                    }
                                } else {
                                    await header.rollback();
                                    let errorResult = new ResultError(400, true, "users.signUp() Error", new Error('Error While Inserting Data'), '');
                                    next(errorResult);
                                }
                            }
                        }
                    }
                } else {
                    // let errorResult = new ResultError(203, true, "User Not Available", new Error("User Not Available"), '');
                    // next(errorResult);
                    let userDevice = authorizationResult.currentUserDevice;
                    let appId: number;
                    if (userDevice.app == 'MatrimonyAdmin') {
                        appId = 1;
                    } else if (userDevice.app == 'MatrimonyAndroid') {
                        appId = 2;
                    } else {
                        appId = 3;
                    }
                    req.body.imageId = req.body.imageId ? req.body.imageId : null;
                    await header.beginTransaction();
                    if (req.body.email) {
                        let checkEmail = `SELECT * FROM users WHERE email = '` + req.body.email + `'`;
                        let checkEmailResult = await header.query(checkEmail);
                        if (checkEmailResult && checkEmailResult.length > 0) {
                            await header.rollback();
                            let successResult = 'Email Already Inserted';
                            return res.status(200).send(successResult);
                        } else {
                            let sql = `INSERT INTO users(contactNo, email, isDisable, referalUserId) VALUES ('` + req.body.contactNo + `','` + req.body.email + `', 0, ` + (req.body.referalUserId ? req.body.referalUserId : null) + `)`;
                            let result = await header.query(sql);
                            if (result && result.insertId > 0) {
                                let userId = result.insertId;
                                let userRoleSql = `INSERT INTO userroles(userId, roleId) VALUES (` + userId + `, 2) `;
                                result = await header.query(userRoleSql);
                                if (result && result.affectedRows > 0) {
                                    if (userDevice) {
                                        userDevice.apiCallTime = userDevice.apiCallTime ? userDevice.apiCallTime : '';
                                        let deviceDetailSql = `INSERT INTO userdevicedetail(userId, applicationId, deviceId, fcmToken, deviceLocation, deviceManufacturer, deviceModel, apiCallTime) VALUES(` + userId + `,` + appId + `,'` + userDevice.deviceId + `','` + userDevice.fcmToken + `','` + userDevice.deviceLocation + `','` + userDevice.deviceManufacturer + `','` + userDevice.deviceModel + `','` + userDevice.apiCallTime + `')`;
                                        let deviceDetailResult = await header.query(deviceDetailSql);
                                    }
                                    let userFlag = await header.query(`SELECT * FROM userflags`);
                                    if (userFlag && userFlag.length > 0) {
                                        for (let index = 0; index < userFlag.length; index++) {
                                            let userFlagSql = `INSERT INTO userflagvalues(userId, userFlagId, userFlagValue) VALUES (` + userId + `, ` + userFlag[index].id + `, ` + userFlag[index].defaultValue + `)`
                                            let userFlagSqlResult = await header.query(userFlagSql);
                                        }
                                    }
                                    let userPerDetailSql = `SELECT u.id, u.firstName, u.middleName, u.lastName, u.gender, u.email, u.contactNo
                                    , upd.birthDate, upd.languages, upd.eyeColor, upd.expectation, upd.aboutMe, upd.weight, upd.profileForId, pf.name as profileForName
                                    , img.imageUrl, r.name as religion, ms.name as maritalStatus, c.name as community, o.name as occupation, e.name as education, sc.name as subCommunity, ai.value as annualIncome, d.name as diet, h.name as height
                                , addr.addressLine1, addr.addressLine2, addr.pincode, addr.cityId, addr.districtId, addr.stateId, addr.countryId
                                , cit.name as cityName, ds.name as districtName, st.name as stateName, cou.name as countryName
                                , em.name as employmentType, DATE_FORMAT(FROM_DAYS(DATEDIFF(now(),upd.birthDate)), '%Y')+0 AS age
                                , addr.latitude, addr.longitude
                                FROM users u
                                LEFT JOIN userroles ur ON ur.userId = u.id
                                LEFT JOIN images img ON img.id = u.imageId
                                LEFT JOIN userpersonaldetail upd ON upd.userId = u.id
                                LEFT JOIN religion r ON r.id = upd.religionId
                                LEFT JOIN maritalstatus ms ON ms.id = upd.maritalStatusId
                                LEFT JOIN community c ON c.id = upd.communityId
                                LEFT JOIN occupation o ON o.id = upd.occupationId
                                LEFT JOIN education e ON e.id = upd.educationId
                                LEFT JOIN subcommunity sc ON sc.id = upd.subCommunityId
                                LEFT JOIN annualincome ai ON ai.id = upd.annualIncomeId
                                LEFT JOIN diet d ON d.id = upd.dietId
                                LEFT JOIN height h ON h.id = upd.heightId
                                LEFT JOIN addresses addr ON addr.id = upd.addressId
                                LEFT JOIN cities cit ON addr.cityId = cit.id
                                LEFT JOIN districts ds ON addr.districtId = ds.id
                                LEFT JOIN state st ON addr.stateId = st.id
                                LEFT JOIN countries cou ON addr.countryId = cou.id
                                LEFT JOIN employmenttype em ON em.id = upd.employmenttypeId
                                LEFT JOIN profilefor pf ON pf.id = upd.profileForId
                                 WHERE ur.roleId = 2 AND u.id =  ` + userId + ``;
                                    let userResult: any = await header.query(userPerDetailSql);
                                    let signJWTResult: any = await signJWT(userResult[0]);
                                    if (signJWTResult && signJWTResult.token) {
                                        userResult[0].token = signJWTResult.token;
                                        let refreshToken = await createRefreshToken(userResult[0]);
                                        //insert refresh token
                                        let insertRefreshTokenSql = `INSERT INTO userrefreshtoken(userId, refreshToken, expireAt) VALUES(?,?,?)`;
                                        insertRefTokenResult = await header.query(insertRefreshTokenSql, [userResult[0].id, refreshToken.token, refreshToken.expireAt]);
                                        if (insertRefTokenResult && insertRefTokenResult.affectedRows > 0) {
                                            userResult[0].refreshToken = refreshToken.token;

                                            let userflagvalues = `SELECT ufv.*, uf.flagName, uf.displayName FROM userflagvalues ufv
                                        LEFT JOIN userflags uf ON uf.id = ufv.userFlagId
                                        WHERE ufv.userId = ` + userId + ``;
                                            userResult[0].userFlags = await header.query(userflagvalues);

                                            let todayDate = new Date();
                                            let date = new Date(todayDate).getFullYear() + "-" + ("0" + (new Date(todayDate).getMonth() + 1)).slice(-2) + "-" + ("0" + new Date(todayDate).getDate()).slice(-2) + "";

                                            let userPackages = `SELECT up.*, p.name as packageName, td.id as timeDurationId, td.value FROM userpackage up
                                        LEFT JOIN package p ON p.id = up.packageId
                                        LEFT JOIN packageduration pd ON pd.id = up.packageDurationId
                                        LEFT JOIN timeduration td ON td.id = pd.timeDurationId
                                            WHERE up.userId = ` + userId + ` order by createdDate DESC`;
                                            let userPackage = await header.query(userPackages);
                                            if (userPackage && userPackage.length > 0) {
                                                for (let k = 0; k < userPackage.length; k++) {
                                                    let packageFacility = await header.query(`SELECT pf.*, pff.name FROM packagefacility pf
                                                LEFT JOIN premiumfacility pff ON pff.id = pf.premiumFacilityId
                                                 WHERE pf.packageId = ` + userPackage[k].packageId);
                                                    userPackage[k].packageFacility = packageFacility;
                                                }
                                            }
                                            userResult[0].userPackage = userPackage[0];

                                            // let minAge = await header.query(`SELECT min(DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0) as minAge
                                            // FROM users u
                                            // LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                                            // LEFT JOIN userroles ur ON ur.userId = u.id
                                            // WHERE ur.roleId = 2 AND u.id != ` + userResult[0].id + ` AND (upa.userId = u.id) AND u.id NOT IN (select userBlockId from userblock where userId = ` + userResult[0].id + `)`);
                                            // let maxAge = await header.query(`SELECT max(DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0) as maxAge
                                            // FROM users u
                                            // LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                                            // LEFT JOIN userroles ur ON ur.userId = u.id
                                            // WHERE ur.roleId = 2 AND u.id != ` + userResult[0].id + ` AND (upa.userId = u.id) AND u.id NOT IN (select userBlockId from userblock where userId = ` + userResult[0].id + `)`);

                                            // let occupationSql = `SELECT * FROM occupation WHERE isActive = 1 AND isDelete = 0`;
                                            // let occupationResult = await header.query(occupationSql);

                                            // let educationSql = `SELECT * FROM education WHERE isActive = 1 AND isDelete = 0`;
                                            // let educationResult = await header.query(educationSql);

                                            // let maritalStatusSql = `SELECT * FROM maritalstatus WHERE isActive = 1 AND isDelete = 0`;
                                            // let maritalStatusResult = await header.query(maritalStatusSql);

                                            // let religionSql = `SELECT * FROM religion WHERE isActive = 1 AND isDelete = 0`;
                                            // let religionResult = await header.query(religionSql);

                                            // let communitySql = `SELECT * FROM community WHERE isActive = 1 AND isDelete = 0`;
                                            // let communityResult = await header.query(communitySql);

                                            // let subCommunitySql = `SELECT * FROM subcommunity WHERE isActive = 1 AND isDelete = 0`;
                                            // let subCommunityResult = await header.query(subCommunitySql);

                                            // let dietSql = `SELECT * FROM diet WHERE isActive = 1 AND isDelete = 0`;
                                            // let dietResult = await header.query(dietSql);

                                            // let heightSql = `SELECT * FROM height WHERE isActive = 1 AND isDelete = 0 order by name`;
                                            // let heightResult = await header.query(heightSql);

                                            // let annualIncomeSql = `SELECT * FROM annualincome WHERE isActive = 1 AND isDelete = 0`;
                                            // let annualIncomeResult = await header.query(annualIncomeSql);

                                            // let employmentTypeSql = `SELECT * FROM employmenttype WHERE isActive = 1 AND isDelete = 0`;
                                            // let employmentTypeResult = await header.query(employmentTypeSql);

                                            // let documentTypeSql = `SELECT * FROM documenttype WHERE isActive = 1 AND isDelete = 0`;
                                            // let documentTypeResult = await header.query(documentTypeSql);

                                            // userResult[0].masterEntryData = {
                                            //     "occupation": occupationResult,
                                            //     "education": educationResult,
                                            //     "maritalStatus": maritalStatusResult,
                                            //     "religion": religionResult,
                                            //     "community": communityResult,
                                            //     "subCommunity": subCommunityResult,
                                            //     "diet": dietResult,
                                            //     "height": heightResult,
                                            //     "annualIncome": annualIncomeResult,
                                            //     "employmentType": employmentTypeResult,
                                            //     "maxAge": maxAge[0].maxAge,
                                            //     "minAge": minAge[0].minAge,
                                            //     "documentType": documentTypeResult
                                            // }

                                            userResult[0].isVerified = false;
                                            let isVerified = true;
                                            let documentsSql = `SELECT ud.*, dt.name as documentTypeName FROM userdocument ud INNER JOIN documenttype dt ON dt.id = ud.documentTypeId WHERE userId = ` + userResult[0].id;
                                            let documentsResult = await header.query(documentsSql);
                                            userResult[0].userDocuments = documentsResult;
                                            if (documentsResult && documentsResult.length > 0) {
                                                for (let j = 0; j < documentsResult.length; j++) {
                                                    if (documentsResult[j].isRequired && !documentsResult[j].isVerified) {
                                                        isVerified = false;
                                                    }
                                                }
                                            } else {
                                                isVerified = false;
                                            }
                                            userResult[0].isVerifiedProfile = isVerified;
                                            userResult[0].isOAuth = false;
                                            userResult[0].isAppleLogin = false;

                                            userResult[0].userWalletAmount = 0;
                                            let getUserWalletSql = `SELECT * FROM userwallets WHERE userId = ` + userResult[0].id;
                                            let getUserWalletResult = await header.query(getUserWalletSql);
                                            if (getUserWalletResult && getUserWalletResult.length > 0) {
                                                userResult[0].userWalletAmount = getUserWalletResult[0].amount
                                            }

                                            await header.commit();
                                            // let successResult = new ResultSuccess(200, true, 'Login User', userResult, 1, "");
                                            // return res.status(200).send(successResult);

                                            //Note: Return 203 Status because in app need to complete profile screen
                                            let successResult = new ResultSuccess(203, true, 'Login User', userResult, 1, "");
                                            return res.status(203).send(successResult);
                                        } else {
                                            await header.rollback();
                                            let errorResult = new ResultError(400, true, "users.signUp() Error", new Error('Error While Login'), '');
                                            next(errorResult);
                                        }
                                    } else {
                                        await header.rollback();
                                        return res.status(401).json({
                                            message: 'Unable to Sign JWT',
                                            error: signJWTResult.error
                                        });
                                    }
                                } else {
                                    await header.rollback();
                                    let errorResult = new ResultError(400, true, "users.signUp() Error", new Error('Error While Inserting Data'), '');
                                    next(errorResult);
                                }
                            } else {
                                await header.rollback();
                                let errorResult = new ResultError(400, true, "users.signUp() Error", new Error('Error While Inserting Data'), '');
                                next(errorResult);
                            }
                        }
                    } else {
                        let checkEmail = `SELECT * FROM users WHERE contactNo = '` + req.body.contactNo + `'`;
                        let checkEmailResult = await header.query(checkEmail);
                        if (checkEmailResult && checkEmailResult.length > 0) {
                            await header.rollback();
                            let successResult = 'ContactNo Already Inserted';
                            return res.status(200).send(successResult);
                        } else {
                            let sql = `INSERT INTO users(contactNo, isDisable, referalUSerId) VALUES ('` + req.body.contactNo + `', 0, ` + (req.body.referalUserId ? req.body.referalUserId : null) + `)`;
                            let result = await header.query(sql);
                            if (result && result.insertId > 0) {
                                let userId = result.insertId;
                                let userRoleSql = `INSERT INTO userroles(userId, roleId) VALUES (` + userId + `, 2) `;
                                result = await header.query(userRoleSql);
                                if (result && result.affectedRows > 0) {
                                    if (userDevice) {
                                        userDevice.apiCallTime = userDevice.apiCallTime ? userDevice.apiCallTime : '';
                                        let deviceDetailSql = `INSERT INTO userdevicedetail(userId, applicationId, deviceId, fcmToken, deviceLocation, deviceManufacturer, deviceModel, apiCallTime) VALUES(` + userId + `,` + appId + `,'` + userDevice.deviceId + `','` + userDevice.fcmToken + `','` + userDevice.deviceLocation + `','` + userDevice.deviceManufacturer + `','` + userDevice.deviceModel + `','` + userDevice.apiCallTime + `')`;
                                        let deviceDetailResult = await header.query(deviceDetailSql);
                                    }
                                    let userFlag = await header.query(`SELECT * FROM userflags`);
                                    if (userFlag && userFlag.length > 0) {
                                        for (let index = 0; index < userFlag.length; index++) {
                                            let userFlagSql = `INSERT INTO userflagvalues(userId, userFlagId, userFlagValue) VALUES (` + userId + `, ` + userFlag[index].id + `, ` + userFlag[index].defaultValue + `)`
                                            let userFlagSqlResult = await header.query(userFlagSql);
                                        }
                                    }
                                    let userPerDetailSql = `SELECT u.id, u.firstName, u.middleName, u.lastName, u.gender, u.email, u.contactNo
                                    , upd.birthDate, upd.languages, upd.eyeColor, upd.expectation, upd.aboutMe, upd.weight, upd.profileForId, pf.name as profileForName
                                    , img.imageUrl, r.name as religion, ms.name as maritalStatus, c.name as community, o.name as occupation, e.name as education, sc.name as subCommunity, ai.value as annualIncome, d.name as diet, h.name as height
                                , addr.addressLine1, addr.addressLine2, addr.pincode, addr.cityId, addr.districtId, addr.stateId, addr.countryId
                                , cit.name as cityName, ds.name as districtName, st.name as stateName, cou.name as countryName
                                , em.name as employmentType, DATE_FORMAT(FROM_DAYS(DATEDIFF(now(),upd.birthDate)), '%Y')+0 AS age
                                , addr.latitude, addr.longitude
                                FROM users u
                                LEFT JOIN userroles ur ON ur.userId = u.id
                                LEFT JOIN images img ON img.id = u.imageId
                                LEFT JOIN userpersonaldetail upd ON upd.userId = u.id
                                LEFT JOIN religion r ON r.id = upd.religionId
                                LEFT JOIN maritalstatus ms ON ms.id = upd.maritalStatusId
                                LEFT JOIN community c ON c.id = upd.communityId
                                LEFT JOIN occupation o ON o.id = upd.occupationId
                                LEFT JOIN education e ON e.id = upd.educationId
                                LEFT JOIN subcommunity sc ON sc.id = upd.subCommunityId
                                LEFT JOIN annualincome ai ON ai.id = upd.annualIncomeId
                                LEFT JOIN diet d ON d.id = upd.dietId
                                LEFT JOIN height h ON h.id = upd.heightId
                                LEFT JOIN addresses addr ON addr.id = upd.addressId
                                LEFT JOIN cities cit ON addr.cityId = cit.id
                                LEFT JOIN districts ds ON addr.districtId = ds.id
                                LEFT JOIN state st ON addr.stateId = st.id
                                LEFT JOIN countries cou ON addr.countryId = cou.id
                                LEFT JOIN employmenttype em ON em.id = upd.employmenttypeId
                                LEFT JOIN profilefor pf ON pf.id = upd.profileForId
                                 WHERE ur.roleId = 2 AND u.id =  ` + userId + ``;
                                    let userResult: any = await header.query(userPerDetailSql);
                                    let signJWTResult: any = await signJWT(userResult[0]);
                                    console.log("HEY")
                                    if (signJWTResult && signJWTResult.token) {
                                        userResult[0].token = signJWTResult.token;
                                        let refreshToken = await createRefreshToken(userResult[0]);
                                        //insert refresh token
                                        let insertRefreshTokenSql = `INSERT INTO userrefreshtoken(userId, refreshToken, expireAt) VALUES(?,?,?)`;
                                        insertRefTokenResult = await header.query(insertRefreshTokenSql, [userResult[0].id, refreshToken.token, refreshToken.expireAt]);
                                        if (insertRefTokenResult && insertRefTokenResult.affectedRows > 0) {
                                            userResult[0].refreshToken = refreshToken.token;

                                            let userflagvalues = `SELECT ufv.*, uf.flagName, uf.displayName FROM userflagvalues ufv
                                        LEFT JOIN userflags uf ON uf.id = ufv.userFlagId
                                        WHERE ufv.userId = ` + userId + ``;
                                            userResult[0].userFlags = await header.query(userflagvalues);

                                            let todayDate = new Date();
                                            let date = new Date(todayDate).getFullYear() + "-" + ("0" + (new Date(todayDate).getMonth() + 1)).slice(-2) + "-" + ("0" + new Date(todayDate).getDate()).slice(-2) + "";

                                            let userPackages = `SELECT up.*, p.name as packageName, td.id as timeDurationId, td.value FROM userpackage up
                                        LEFT JOIN package p ON p.id = up.packageId
                                        LEFT JOIN packageduration pd ON pd.id = up.packageDurationId
                                        LEFT JOIN timeduration td ON td.id = pd.timeDurationId
                                            WHERE up.userId = ` + userId + ` order by createdDate DESC`;
                                            let userPackage = await header.query(userPackages);
                                            if (userPackage && userPackage.length > 0) {
                                                for (let k = 0; k < userPackage.length; k++) {
                                                    let packageFacility = await header.query(`SELECT pf.*, pff.name FROM packagefacility pf
                                                LEFT JOIN premiumfacility pff ON pff.id = pf.premiumFacilityId
                                                 WHERE pf.packageId = ` + userPackage[k].packageId);
                                                    userPackage[k].packageFacility = packageFacility;
                                                }
                                            }
                                            userResult[0].userPackage = userPackage[0];

                                            // let minAge = await header.query(`SELECT min(DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0) as minAge
                                            // FROM users u
                                            // LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                                            // LEFT JOIN userroles ur ON ur.userId = u.id
                                            // WHERE ur.roleId = 2 AND u.id != ` + userResult[0].id + ` AND (upa.userId = u.id) AND u.id NOT IN (select userBlockId from userblock where userId = ` + userResult[0].id + `)`);
                                            // let maxAge = await header.query(`SELECT max(DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0) as maxAge
                                            // FROM users u
                                            // LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                                            // LEFT JOIN userroles ur ON ur.userId = u.id
                                            // WHERE ur.roleId = 2 AND u.id != ` + userResult[0].id + ` AND (upa.userId = u.id) AND u.id NOT IN (select userBlockId from userblock where userId = ` + userResult[0].id + `)`);

                                            // let occupationSql = `SELECT * FROM occupation WHERE isActive = 1 AND isDelete = 0`;
                                            // let occupationResult = await header.query(occupationSql);

                                            // let educationSql = `SELECT * FROM education WHERE isActive = 1 AND isDelete = 0`;
                                            // let educationResult = await header.query(educationSql);

                                            // let maritalStatusSql = `SELECT * FROM maritalstatus WHERE isActive = 1 AND isDelete = 0`;
                                            // let maritalStatusResult = await header.query(maritalStatusSql);

                                            // let religionSql = `SELECT * FROM religion WHERE isActive = 1 AND isDelete = 0`;
                                            // let religionResult = await header.query(religionSql);

                                            // let communitySql = `SELECT * FROM community WHERE isActive = 1 AND isDelete = 0`;
                                            // let communityResult = await header.query(communitySql);

                                            // let subCommunitySql = `SELECT * FROM subcommunity WHERE isActive = 1 AND isDelete = 0`;
                                            // let subCommunityResult = await header.query(subCommunitySql);

                                            // let dietSql = `SELECT * FROM diet WHERE isActive = 1 AND isDelete = 0`;
                                            // let dietResult = await header.query(dietSql);

                                            // let heightSql = `SELECT * FROM height WHERE isActive = 1 AND isDelete = 0 order by name`;
                                            // let heightResult = await header.query(heightSql);

                                            // let annualIncomeSql = `SELECT * FROM annualincome WHERE isActive = 1 AND isDelete = 0`;
                                            // let annualIncomeResult = await header.query(annualIncomeSql);

                                            // let employmentTypeSql = `SELECT * FROM employmenttype WHERE isActive = 1 AND isDelete = 0`;
                                            // let employmentTypeResult = await header.query(employmentTypeSql);

                                            // let documentTypeSql = `SELECT * FROM documenttype WHERE isActive = 1 AND isDelete = 0`;
                                            // let documentTypeResult = await header.query(documentTypeSql);

                                            // userResult[0].masterEntryData = {
                                            //     "occupation": occupationResult,
                                            //     "education": educationResult,
                                            //     "maritalStatus": maritalStatusResult,
                                            //     "religion": religionResult,
                                            //     "community": communityResult,
                                            //     "subCommunity": subCommunityResult,
                                            //     "diet": dietResult,
                                            //     "height": heightResult,
                                            //     "annualIncome": annualIncomeResult,
                                            //     "employmentType": employmentTypeResult,
                                            //     "maxAge": maxAge[0].maxAge,
                                            //     "minAge": minAge[0].minAge,
                                            //     "documentType": documentTypeResult
                                            // }

                                            userResult[0].isVerified = false;
                                            let isVerified = true;
                                            let documentsSql = `SELECT ud.*, dt.name as documentTypeName FROM userdocument ud INNER JOIN documenttype dt ON dt.id = ud.documentTypeId WHERE userId = ` + userResult[0].id;
                                            let documentsResult = await header.query(documentsSql);
                                            userResult[0].userDocuments = documentsResult;
                                            if (documentsResult && documentsResult.length > 0) {
                                                for (let j = 0; j < documentsResult.length; j++) {
                                                    if (documentsResult[j].isRequired && !documentsResult[j].isVerified) {
                                                        isVerified = false;
                                                    }
                                                }
                                            } else {
                                                isVerified = false;
                                            }
                                            userResult[0].isVerifiedProfile = isVerified;

                                            userResult[0].isOAuth = false;
                                            userResult[0].isAppleLogin = false;

                                            userResult[0].userWalletAmount = 0;
                                            let getUserWalletSql = `SELECT * FROM userwallets WHERE userId = ` + userResult[0].id;
                                            let getUserWalletResult = await header.query(getUserWalletSql);
                                            if (getUserWalletResult && getUserWalletResult.length > 0) {
                                                userResult[0].userWalletAmount = getUserWalletResult[0].amount
                                            }

                                            await header.commit();
                                            // let successResult = new ResultSuccess(200, true, 'Login User', userResult, 1, "");
                                            // return res.status(200).send(successResult);

                                            //Note: Return 203 Status because in app need to complete profile screen
                                            let successResult = new ResultSuccess(203, true, 'Login User', userResult, 1, "");
                                            return res.status(203).send(successResult);
                                        } else {
                                            await header.rollback();
                                            let errorResult = new ResultError(400, true, "users.signUp() Error", new Error('Error While Login'), '');
                                            next(errorResult);
                                        }
                                    } else {
                                        await header.rollback();
                                        return res.status(401).json({
                                            message: 'Unable to Sign JWT',
                                            error: signJWTResult.error
                                        });
                                    }
                                } else {
                                    await header.rollback();
                                    let errorResult = new ResultError(400, true, "users.signUp() Error", new Error('Error While Inserting Data'), '');
                                    next(errorResult);
                                }
                            } else {
                                await header.rollback();
                                let errorResult = new ResultError(400, true, "users.signUp() Error", new Error('Error While Inserting Data'), '');
                                next(errorResult);
                            }
                        }
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
    } catch (error) {

    }
};

const validateAuthToken = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Validate auth token');
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) {
            let currentUser = authorizationResult.currentUser
            let userDevice = authorizationResult.currentUserDevice;
            let deviceDetailResult;
            let appId: number;
            if (userDevice.app == 'MatrimonyAdmin') {
                appId = 1;
            } else if (userDevice.app == 'MatrimonyAndroid') {
                appId = 2;
            } else {
                appId = 3;
            }
            await header.beginTransaction();
            let userId: number;
            let insertRefTokenResult;

            let sql = `SELECT u.*, ur.roleId, img.imageUrl FROM users u
                LEFT JOIN userroles ur ON ur.userId = u.id
                LEFT JOIN images img ON img.id =u.imageId
                WHERE u.id = `+ currentUser.id + ` AND u.isActive = true AND ur.roleId = 2`;
            let result = await header.query(sql);
            let userPerDetailSql = `SELECT u.id, u.firstName, u.middleName, u.lastName, u.gender, u.email, u.contactNo
            , upd.birthDate, upd.languages, upd.eyeColor, upd.expectation, upd.aboutMe, upd.weight, upd.profileForId, pf.name as profileForName
            , img.imageUrl, r.name as religion, ms.name as maritalStatus, c.name as community, o.name as occupation, e.name as education, sc.name as subCommunity
            , ai.value as annualIncome, d.name as diet, h.name as height
            , addr.addressLine1, addr.addressLine2, addr.pincode, addr.cityId, addr.districtId, addr.stateId, addr.countryId
            , cit.name as cityName, ds.name as districtName, st.name as stateName, cou.name as countryName
            , em.name as employmentType, DATE_FORMAT(FROM_DAYS(DATEDIFF(now(),upd.birthDate)), '%Y')+0 AS age
            , addr.latitude, addr.longitude
                FROM users u
                LEFT JOIN userroles ur ON ur.userId = u.id
                LEFT JOIN images img ON img.id = u.imageId
                LEFT JOIN userpersonaldetail upd ON upd.userId = u.id
                LEFT JOIN religion r ON r.id = upd.religionId
                LEFT JOIN maritalstatus ms ON ms.id = upd.maritalStatusId
                LEFT JOIN community c ON c.id = upd.communityId
                LEFT JOIN occupation o ON o.id = upd.occupationId
                LEFT JOIN education e ON e.id = upd.educationId
                LEFT JOIN subcommunity sc ON sc.id = upd.subCommunityId
                LEFT JOIN annualincome ai ON ai.id = upd.annualIncomeId
                LEFT JOIN diet d ON d.id = upd.dietId
                LEFT JOIN height h ON h.id = upd.heightId
                LEFT JOIN addresses addr ON addr.id = upd.addressId
                LEFT JOIN cities cit ON addr.cityId = cit.id
                LEFT JOIN districts ds ON addr.districtId = ds.id
                LEFT JOIN state st ON addr.stateId = st.id
                LEFT JOIN countries cou ON addr.countryId = cou.id
                LEFT JOIN employmenttype em ON em.id = upd.employmenttypeId
                LEFT JOIN profilefor pf ON pf.id = upd.profileForId
                 WHERE ur.roleId = 2
                  AND u.id = `+ currentUser.id;
            let userResult = await header.query(userPerDetailSql);
            if (result && result.length > 0) {
                let checkbloclsql = `SELECT * FROM userblockrequest WHERE blockRequestUserId = ` + result[0].id;
                let checkbloclResult = await header.query(checkbloclsql);
                if (checkbloclResult && checkbloclResult.length > 0) {
                    let successResult = new ResultSuccess(401, true, 'Your account was bloacked', [], 1, "");
                    return res.status(200).send(successResult);
                } else {
                    if (result[0].isDisable) {
                        let errorResult = new ResultError(400, true, "users.login() Error", new Error('Your profile was block by Admin. You cannot login.'), '');
                        next(errorResult);
                    } else {
                        userId = result[0].id;
                        if (result && result.length > 0) {
                            // bcryptjs.compare(req.body.password, result[0].password, async (error, hashresult: any) => {
                            //     if (hashresult == false) {
                            //         return res.status(401).json({
                            //             message: 'Password Mismatch'
                            //         });
                            //     } else if (hashresult) {
                            //         let signJWTResult: any = await signJWT(result[0]);
                            //         if (signJWTResult && signJWTResult.token) {
                            let authorization = '';
                            if (req.headers['authorization'] != undefined && req.headers['authorization'] != '') {
                                let authorizationHeader = req.headers['authorization'];
                                if (authorizationHeader.indexOf('|') > 0) {
                                    authorization = authorizationHeader.split('|')[1];
                                } else {
                                    authorization = authorizationHeader;
                                }
                                if (authorization != '') {
                                    let token = authorization?.split(' ')[1];
                                    userResult[0].token = token;
                                }
                            }

                            if (userDevice) {
                                let checkDeviceSql = `SELECT * FROM userdevicedetail WHERE userId = ` + userId + ``;
                                result = await header.query(checkDeviceSql);
                                userDevice.apiCallTime = userDevice.apiCallTime ? userDevice.apiCallTime : '';
                                if (result && result.length > 0) {
                                    let updateDetailSql = `UPDATE userdevicedetail SET userId = ` + userId + `,applicationId = ` + appId + `,deviceId = '` + userDevice.deviceId + `',fcmToken = '` + userDevice.fcmToken + `',deviceLocation = '` + userDevice.deviceLocation + `',deviceManufacturer = '` + userDevice.deviceManufacturer + `',deviceModel = '` + userDevice.deviceModel + `',apiCallTime = '` + userDevice.apiCallTime + `' WHERE userId = ` + userId;
                                    result = await header.query(updateDetailSql);
                                } else {
                                    let insertDetailSql = `INSERT INTO userdevicedetail(userId, applicationId, deviceId, fcmToken, deviceLocation, deviceManufacturer, deviceModel, apiCallTime) VALUES(` + userId + `,` + appId + `,'` + userDevice.deviceId + `','` + userDevice.fcmToken + `','` + userDevice.deviceLocation + `','` + userDevice.deviceManufacturer + `','` + userDevice.deviceModel + `','` + userDevice.apiCallTime + `')`;
                                    result = await header.query(insertDetailSql);
                                }
                            }
                            let refreshToken = await createRefreshToken(userResult[0]);
                            //insert refresh token
                            let insertRefreshTokenSql = `INSERT INTO userrefreshtoken(userId, refreshToken, expireAt) VALUES(?,?,?)`;
                            insertRefTokenResult = await header.query(insertRefreshTokenSql, [userResult[0].id, refreshToken.token, refreshToken.expireAt]);
                            if (insertRefTokenResult && insertRefTokenResult.affectedRows > 0) {
                                userResult[0].refreshToken = refreshToken.token;

                                let userflagvalues = `SELECT ufv.*, uf.flagName, uf.displayName FROM userflagvalues ufv
                                        LEFT JOIN userflags uf ON uf.id = ufv.userFlagId
                                        WHERE ufv.userId = ` + userId + ``;
                                userResult[0].userFlags = await header.query(userflagvalues);

                                let todayDate = new Date();
                                let date = new Date(todayDate).getFullYear() + "-" + ("0" + (new Date(todayDate).getMonth() + 1)).slice(-2) + "-" + ("0" + new Date(todayDate).getDate()).slice(-2) + "";

                                let userPackages = `SELECT up.*, p.name as packageName, td.id as timeDurationId, td.value, p.weightage FROM userpackage up
                                            LEFT JOIN package p ON p.id = up.packageId
                                            LEFT JOIN packageduration pd ON pd.id = up.packageDurationId
                                            LEFT JOIN timeduration td ON td.id = pd.timeDurationId
                                            WHERE up.userId = ` + userId + ` AND DATE(up.startDate) <= DATE(CURRENT_TIMESTAMP()) AND DATE(up.endDate) >= DATE(CURRENT_TIMESTAMP())
                                            order by p.weightage DESC`;
                                let userPackage = await header.query(userPackages);
                                if (userPackage && userPackage.length > 0) {
                                    for (let k = 0; k < userPackage.length; k++) {
                                        let packageFacility = await header.query(`SELECT pf.*, pff.name FROM packagefacility pf
                                                    LEFT JOIN premiumfacility pff ON pff.id = pf.premiumFacilityId
                                                     WHERE pf.packageId = ` + userPackage[k].packageId);
                                        userPackage[k].packageFacility = packageFacility;
                                    }
                                }
                                userResult[0].userPackage = userPackage[0];

                                //     let minAge = await header.query(`SELECT min(DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0) as minAge
                                // FROM users u
                                // LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                                // LEFT JOIN userroles ur ON ur.userId = u.id
                                // WHERE ur.roleId = 2 AND u.id != ` + userResult[0].id + ` AND (upa.userId = u.id) 
                                // AND u.id NOT IN (select userBlockId from userblock where userId = ` + userResult[0].id + `)`);
                                //     let maxAge = await header.query(`SELECT max(DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0) as maxAge
                                // FROM users u
                                // LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                                // LEFT JOIN userroles ur ON ur.userId = u.id
                                // WHERE ur.roleId = 2 AND u.id != ` + userResult[0].id + ` AND (upa.userId = u.id) 
                                // AND u.id NOT IN (select userBlockId from userblock where userId = ` + userResult[0].id + `)`);

                                //     let ageList = [];
                                //     for (let i = 18; i <= 60; i++) {
                                //         ageList.push(i)
                                //     }
                                //     console.log(ageList)

                                // let cityName = await header.query(`select (cityName) FROM addresses where cityName is not null or cityName !='' group by cityName  having  cityName !=''`)

                                // let occupationSql = `SELECT * FROM occupation WHERE isActive = 1 AND isDelete = 0`;
                                // let occupationResult = await header.query(occupationSql);

                                // let educationSql = `SELECT * FROM education WHERE isActive = 1 AND isDelete = 0`;
                                // let educationResult = await header.query(educationSql);

                                // let maritalStatusSql = `SELECT * FROM maritalstatus WHERE isActive = 1 AND isDelete = 0`;
                                // let maritalStatusResult = await header.query(maritalStatusSql);

                                // let religionSql = `SELECT * FROM religion WHERE isActive = 1 AND isDelete = 0`;
                                // let religionResult = await header.query(religionSql);

                                // let communitySql = `SELECT * FROM community WHERE isActive = 1 AND isDelete = 0`;
                                // let communityResult = await header.query(communitySql);

                                // let subCommunitySql = `SELECT * FROM subcommunity WHERE isActive = 1 AND isDelete = 0`;
                                // let subCommunityResult = await header.query(subCommunitySql);

                                // let dietSql = `SELECT * FROM diet WHERE isActive = 1 AND isDelete = 0`;
                                // let dietResult = await header.query(dietSql);

                                // let heightSql = `SELECT * FROM height WHERE isActive = 1 AND isDelete = 0 order by name`;
                                // let heightResult = await header.query(heightSql);

                                // let annualIncomeSql = `SELECT * FROM annualincome WHERE isActive = 1 AND isDelete = 0`;
                                // let annualIncomeResult = await header.query(annualIncomeSql);

                                // let employmentTypeSql = `SELECT * FROM employmenttype WHERE isActive = 1 AND isDelete = 0`;
                                // let employmentTypeResult = await header.query(employmentTypeSql);

                                // let documentTypeSql = `SELECT * FROM documenttype WHERE isActive = 1 AND isDelete = 0`;
                                // let documentTypeResult = await header.query(documentTypeSql);

                                // userResult[0].masterEntryData = {
                                //     "occupation": occupationResult,
                                //     "education": educationResult,
                                //     "maritalStatus": maritalStatusResult,
                                //     "religion": religionResult,
                                //     "community": communityResult,
                                //     "subCommunity": subCommunityResult,
                                //     "diet": dietResult,
                                //     "height": heightResult,
                                //     "annualIncome": annualIncomeResult,
                                //     "employmentType": employmentTypeResult,
                                //     "maxAge": maxAge[0].maxAge,
                                //     "minAge": minAge[0].minAge,
                                //     "ageList": ageList,
                                //     "cityName": cityName,
                                //     "documentType": documentTypeResult
                                // }


                                userResult[0].isVerified = false;
                                let isVerified = true;
                                let documentsSql = `SELECT ud.*, dt.name as documentTypeName FROM userdocument ud INNER JOIN documenttype dt ON dt.id = ud.documentTypeId WHERE userId = ` + userResult[0].id;
                                let documentsResult = await header.query(documentsSql);
                                userResult[0].userDocuments = documentsResult;
                                if (documentsResult && documentsResult.length > 0) {
                                    for (let j = 0; j < documentsResult.length; j++) {
                                        if (documentsResult[j].isRequired && !documentsResult[j].isVerified) {
                                            isVerified = false;
                                        }
                                    }
                                } else {
                                    isVerified = false;
                                }
                                userResult[0].isVerifiedProfile = isVerified;

                                let getUserAuthSql = `SELECT * FROM userauthdata WHERE userId = ` + userResult[0].id;
                                let getUserAuthResult = await header.query(getUserAuthSql)
                                userResult[0].isOAuth = (getUserAuthResult && getUserAuthResult.length > 0) ? true : false;
                                userResult[0].isAppleLogin = (getUserAuthResult && getUserAuthResult.length > 0 && getUserAuthResult[0].authProviderId == 3) ? true : false;

                                userResult[0].userWalletAmount = 0;
                                let getUserWalletSql = `SELECT * FROM userwallets WHERE userId = ` + userResult[0].id;
                                let getUserWalletResult = await header.query(getUserWalletSql);
                                if (getUserWalletResult && getUserWalletResult.length > 0) {
                                    userResult[0].userWalletAmount = getUserWalletResult[0].amount
                                }

                                await header.commit();
                                let successResult = new ResultSuccess(200, true, 'Login User', userResult, 1, "");
                                return res.status(200).send(successResult);
                            } else {
                                await header.rollback();
                                let errorResult = new ResultError(400, true, "users.signUp() Error", new Error('Error While Login'), '');
                                next(errorResult);
                            }
                            //         } else {
                            //             return res.status(401).json({
                            //                 message: 'Unable to Sign JWT',
                            //                 error: signJWTResult.error
                            //             });
                            //         }
                            //     }
                            // });
                        } else {
                            await header.rollback();
                            let errorResult = new ResultError(400, true, "users.login() Error", new Error('Error While Login'), '');
                            next(errorResult);
                        }
                    }

                }
            } else {
                let successResult = new ResultSuccess(200, true, 'Email is incorrect!', [], 1, "");
                return res.status(200).send(successResult);
            }

        } else {
            let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'users.validateAuthToken() Exception', error, '');
        next(errorResult);
    }
}

const validateAuthTokenOld = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Validate auth token');
        let authorization = '';
        if (req.headers['authorization'] != undefined && req.headers['authorization'] != '') {
            let authorizationHeader = req.headers['authorization'];
            if (authorizationHeader.indexOf('|') > 0) {
                authorization = authorizationHeader.split('|')[1];
            } else {
                authorization = authorizationHeader;
            }
            if (authorization != '') {
                let token = authorization?.split(' ')[1];
                if (token) {
                    await jwt.verify(token, config.server.token.secret, async (error: any, decoded: any) => {
                        if (error) {
                            let errorResult = new ResultError(401, true, "Unauthorized request", new Error("Unauthorized request"), '');
                            next(errorResult);
                        } else {
                            let decodeVal = decoded;
                            let currentUser;//= await getcurrentUser(decodeVal.userId);
                            let userSql = `SELECT * FROM users WHERE id = ` + decodeVal.userId;
                            let userResult = await header.query(userSql);
                            if (userResult && userResult.length > 0) {
                                let roleSql = `SELECT roleId,roles.name as roleName FROM userroles INNER JOIN roles  ON  roles.id = userroles.roleId LEFT JOIN userdevicedetail ON userdevicedetail.userId = userroles.userId WHERE userId =` + decodeVal.userId;
                                let roleResult = await header.query(roleSql);
                                let roles = {
                                    id: roleResult[0].roleId,
                                    name: roleResult[0].roleName
                                };

                                let data = new Users(
                                    userResult[0].id,
                                    userResult[0].firstName,
                                    userResult[0].middleName,
                                    userResult[0].lastName,
                                    userResult[0].contactNo,
                                    userResult[0].email,
                                    userResult[0].gender,
                                    userResult[0].password,
                                    userResult[0].imageId,
                                    userResult[0].isPasswordSet,
                                    userResult[0].isDisable,
                                    userResult[0].isVerified,
                                    userResult[0].isActive,
                                    userResult[0].isDelete,
                                    userResult[0].createdDate,
                                    userResult[0].modifiedDate,
                                    userResult[0].createdBy,
                                    userResult[0].modifiedBy,
                                    roles.id,
                                    roles,
                                    "",
                                    roleResult[0].applicationId

                                );
                                currentUser = data;
                                currentUser.token = token;
                                let successResult = new ResultSuccess(200, true, "Session Validate", [currentUser, currentUser.token], 1, "null");
                                return res.status(200).send(successResult);
                            } else {
                                let errorResult = new ResultError(300, true, "User not available.", new Error("User not available."), '');
                                next(errorResult);
                            }
                        }
                    });
                } else {
                    let errorResult = new ResultError(300, true, "Authorization header is required.", new Error("Authorization header is required."), '');
                    next(errorResult);
                }
            } else {
                let errorResult = new ResultError(300, true, "Authorization header is required.", new Error("Authorization header is required."), '');
                next(errorResult);
            }
        } else {
            let errorResult = new ResultError(401, true, "Unauthorized request", new Error("Unauthorized request"), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'users.validateAuthToken() Exception', error, '');
        next(errorResult);
    }
}

const registerViaPhone = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Sign Up Via Phone');
        let insertRefTokenResult;
        let deviceDetailResult;
        let requiredFields = ['email', 'contactNo'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let userDevice = authorizationResult.currentUserDevice;
                let appId: number;
                if (userDevice.app == 'MatrimonyAdmin') {
                    appId = 1;
                } else if (userDevice.app == 'MatrimonyAndroid') {
                    appId = 2;
                } else {
                    appId = 3;
                }
                req.body.imageId = req.body.imageId ? req.body.imageId : null;
                await header.beginTransaction()
                let checkEmail = `SELECT * FROM users WHERE email = '` + req.body.email + `'`;
                let checkEmailResult = await header.query(checkEmail);
                if (checkEmailResult && checkEmailResult.length > 0) {
                    await header.rollback();
                    let successResult = 'Email Already Inserted';
                    return res.status(200).send(successResult);
                } else {
                    let sql = `INSERT INTO users(contactNo, email, isDisable, referalUserId) VALUES ('` + req.body.contactNo + `','` + req.body.email + `', 0, ` + (req.body.referalUserId ? req.body.referalUserId : null) + `)`;
                    let result = await header.query(sql);
                    if (result && result.insertId > 0) {
                        let userId = result.insertId;
                        let userRoleSql = `INSERT INTO userroles(userId, roleId) VALUES (` + userId + `, 2) `;
                        result = await header.query(userRoleSql);
                        if (result && result.affectedRows > 0) {
                            if (userDevice) {
                                userDevice.apiCallTime = userDevice.apiCallTime ? userDevice.apiCallTime : '';
                                let deviceDetailSql = `INSERT INTO userdevicedetail(userId, applicationId, deviceId, fcmToken, deviceLocation, deviceManufacturer, deviceModel, apiCallTime) VALUES(` + userId + `,` + appId + `,'` + userDevice.deviceId + `','` + userDevice.fcmToken + `','` + userDevice.deviceLocation + `','` + userDevice.deviceManufacturer + `','` + userDevice.deviceModel + `','` + userDevice.apiCallTime + `')`;
                                deviceDetailResult = await header.query(deviceDetailSql);
                            }
                            let userFlag = await header.query(`SELECT * FROM userflags`);
                            if (userFlag && userFlag.length > 0) {
                                for (let index = 0; index < userFlag.length; index++) {
                                    let userFlagSql = `INSERT INTO userflagvalues(userId, userFlagId, userFlagValue) VALUES (` + userId + `, ` + userFlag[index].id + `, ` + userFlag[index].defaultValue + `)`
                                    let userFlagSqlResult = await header.query(userFlagSql);
                                }
                            }
                            let userPerDetailSql = `SELECT u.id, u.firstName, u.middleName, u.lastName, u.gender, u.email, u.contactNo
                            , upd.birthDate, upd.languages, upd.eyeColor, upd.expectation, upd.aboutMe, upd.weight, upd.profileForId, pf.name as profileForName
                            , img.imageUrl, r.name as religion, ms.name as maritalStatus, c.name as community, o.name as occupation, e.name as education, sc.name as subCommunity, ai.value as annualIncome, d.name as diet, h.name as height
                            , addr.addressLine1, addr.addressLine2, addr.pincode, addr.cityId, addr.districtId, addr.stateId, addr.countryId
                            , cit.name as cityName, ds.name as districtName, st.name as stateName, cou.name as countryName
                            , em.name as employmentType, DATE_FORMAT(FROM_DAYS(DATEDIFF(now(),upd.birthDate)), '%Y')+0 AS age
                            , addr.latitude, addr.longitude
                                FROM users u
                                LEFT JOIN userroles ur ON ur.userId = u.id
                                LEFT JOIN images img ON img.id = u.imageId
                                LEFT JOIN userpersonaldetail upd ON upd.userId = u.id
                                LEFT JOIN religion r ON r.id = upd.religionId
                                LEFT JOIN maritalstatus ms ON ms.id = upd.maritalStatusId
                                LEFT JOIN community c ON c.id = upd.communityId
                                LEFT JOIN occupation o ON o.id = upd.occupationId
                                LEFT JOIN education e ON e.id = upd.educationId
                                LEFT JOIN subcommunity sc ON sc.id = upd.subCommunityId
                                LEFT JOIN annualincome ai ON ai.id = upd.annualIncomeId
                                LEFT JOIN diet d ON d.id = upd.dietId
                                LEFT JOIN height h ON h.id = upd.heightId
                                LEFT JOIN addresses addr ON addr.id = upd.addressId
                                LEFT JOIN cities cit ON addr.cityId = cit.id
                                LEFT JOIN districts ds ON addr.districtId = ds.id
                                LEFT JOIN state st ON addr.stateId = st.id
                                LEFT JOIN countries cou ON addr.countryId = cou.id
                                LEFT JOIN employmenttype em ON em.id = upd.employmenttypeId
                                LEFT JOIN profilefor pf ON pf.id = upd.profileForId
                                 WHERE ur.roleId = 2 AND u.id =  ` + userId + ``;
                            let userResult: any = await header.query(userPerDetailSql);
                            let signJWTResult: any = await signJWT(userResult[0]);
                            if (signJWTResult && signJWTResult.token) {
                                userResult[0].token = signJWTResult.token;
                                let refreshToken = await createRefreshToken(userResult[0]);
                                //insert refresh token
                                let insertRefreshTokenSql = `INSERT INTO userrefreshtoken(userId, refreshToken, expireAt) VALUES(?,?,?)`;
                                insertRefTokenResult = await header.query(insertRefreshTokenSql, [userResult[0].id, refreshToken.token, refreshToken.expireAt]);
                                if (insertRefTokenResult && insertRefTokenResult.affectedRows > 0) {
                                    userResult[0].refreshToken = refreshToken.token;

                                    let userflagvalues = `SELECT ufv.*, uf.flagName, uf.displayName FROM userflagvalues ufv
                                        LEFT JOIN userflags uf ON uf.id = ufv.userFlagId
                                        WHERE ufv.userId = ` + userId + ``;
                                    userResult[0].userFlags = await header.query(userflagvalues);

                                    let todayDate = new Date();
                                    let date = new Date(todayDate).getFullYear() + "-" + ("0" + (new Date(todayDate).getMonth() + 1)).slice(-2) + "-" + ("0" + new Date(todayDate).getDate()).slice(-2) + "";

                                    let userPackages = `SELECT up.*, p.name as packageName, td.id as timeDurationId, td.value FROM userpackage up
                                        LEFT JOIN package p ON p.id = up.packageId
                                        LEFT JOIN packageduration pd ON pd.id = up.packageDurationId
                                        LEFT JOIN timeduration td ON td.id = pd.timeDurationId
                                            WHERE up.userId = ` + userId + ` order by createdDate DESC`;
                                    let userPackage = await header.query(userPackages);
                                    if (userPackage && userPackage.length > 0) {
                                        for (let k = 0; k < userPackage.length; k++) {
                                            let packageFacility = await header.query(`SELECT pf.*, pff.name FROM packagefacility pf
                                                LEFT JOIN premiumfacility pff ON pff.id = pf.premiumFacilityId
                                                 WHERE pf.packageId = ` + userPackage[k].packageId);
                                            userPackage[k].packageFacility = packageFacility;
                                        }
                                    }
                                    userResult[0].userPackage = userPackage[0];

                                    // let minAge = await header.query(`SELECT min(DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0) as minAge
                                    //         FROM users u
                                    //         LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                                    //         LEFT JOIN userroles ur ON ur.userId = u.id
                                    //         WHERE ur.roleId = 2 AND u.id != ` + userResult[0].id + ` AND (upa.userId = u.id) AND u.id NOT IN (select userBlockId from userblock where userId = ` + userResult[0].id + `)`);
                                    // let maxAge = await header.query(`SELECT max(DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0) as maxAge
                                    //         FROM users u
                                    //         LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                                    //         LEFT JOIN userroles ur ON ur.userId = u.id
                                    //         WHERE ur.roleId = 2 AND u.id != ` + userResult[0].id + ` AND (upa.userId = u.id) AND u.id NOT IN (select userBlockId from userblock where userId = ` + userResult[0].id + `)`);

                                    // let occupationSql = `SELECT * FROM occupation WHERE isActive = 1 AND isDelete = 0`;
                                    // let occupationResult = await header.query(occupationSql);

                                    // let educationSql = `SELECT * FROM education WHERE isActive = 1 AND isDelete = 0`;
                                    // let educationResult = await header.query(educationSql);

                                    // let maritalStatusSql = `SELECT * FROM maritalstatus WHERE isActive = 1 AND isDelete = 0`;
                                    // let maritalStatusResult = await header.query(maritalStatusSql);

                                    // let religionSql = `SELECT * FROM religion WHERE isActive = 1 AND isDelete = 0`;
                                    // let religionResult = await header.query(religionSql);

                                    // let communitySql = `SELECT * FROM community WHERE isActive = 1 AND isDelete = 0`;
                                    // let communityResult = await header.query(communitySql);

                                    // let subCommunitySql = `SELECT * FROM subcommunity WHERE isActive = 1 AND isDelete = 0`;
                                    // let subCommunityResult = await header.query(subCommunitySql);

                                    // let dietSql = `SELECT * FROM diet WHERE isActive = 1 AND isDelete = 0`;
                                    // let dietResult = await header.query(dietSql);

                                    // let heightSql = `SELECT * FROM height WHERE isActive = 1 AND isDelete = 0 order by name`;
                                    // let heightResult = await header.query(heightSql);

                                    // let annualIncomeSql = `SELECT * FROM annualincome WHERE isActive = 1 AND isDelete = 0`;
                                    // let annualIncomeResult = await header.query(annualIncomeSql);

                                    // let employmentTypeSql = `SELECT * FROM employmenttype WHERE isActive = 1 AND isDelete = 0`;
                                    // let employmentTypeResult = await header.query(employmentTypeSql);

                                    // let documentTypeSql = `SELECT * FROM documenttype WHERE isActive = 1 AND isDelete = 0`;
                                    // let documentTypeResult = await header.query(documentTypeSql);

                                    // userResult[0].masterEntryData = {
                                    //     "occupation": occupationResult,
                                    //     "education": educationResult,
                                    //     "maritalStatus": maritalStatusResult,
                                    //     "religion": religionResult,
                                    //     "community": communityResult,
                                    //     "subCommunity": subCommunityResult,
                                    //     "diet": dietResult,
                                    //     "height": heightResult,
                                    //     "annualIncome": annualIncomeResult,
                                    //     "employmentType": employmentTypeResult,
                                    //     "maxAge": maxAge[0].maxAge,
                                    //     "minAge": minAge[0].minAge,
                                    //     "documentType": documentTypeResult
                                    // }

                                    userResult[0].isVerified = false;
                                    let isVerified = true;
                                    let documentsSql = `SELECT ud.*, dt.name as documentTypeName FROM userdocument ud INNER JOIN documenttype dt ON dt.id = ud.documentTypeId WHERE userId = ` + userResult[0].id;
                                    let documentsResult = await header.query(documentsSql);
                                    userResult[0].userDocuments = documentsResult;
                                    if (documentsResult && documentsResult.length > 0) {
                                        for (let j = 0; j < documentsResult.length; j++) {
                                            if (documentsResult[j].isRequired && !documentsResult[j].isVerified) {
                                                isVerified = false;
                                            }
                                        }
                                    } else {
                                        isVerified = false;
                                    }
                                    userResult[0].isVerifiedProfile = isVerified;

                                    let getUserAuthSql = `SELECT * FROM userauthdata WHERE userId = ` + userResult[0].id;
                                    let getUserAuthResult = await header.query(getUserAuthSql)
                                    userResult[0].isOAuth = (getUserAuthResult && getUserAuthResult.length > 0) ? true : false;
                                    userResult[0].isAppleLogin = (getUserAuthResult && getUserAuthResult.length > 0 && getUserAuthResult[0].authProviderId == 3) ? true : false;

                                    userResult[0].userWalletAmount = 0;
                                    let getUserWalletSql = `SELECT * FROM userwallets WHERE userId = ` + userResult[0].id;
                                    let getUserWalletResult = await header.query(getUserWalletSql);
                                    if (getUserWalletResult && getUserWalletResult.length > 0) {
                                        userResult[0].userWalletAmount = getUserWalletResult[0].amount
                                    }

                                    await header.commit();
                                    let successResult = new ResultSuccess(200, true, 'Login User', userResult, 1, "");
                                    return res.status(200).send(successResult);
                                } else {
                                    await header.rollback();
                                    let errorResult = new ResultError(400, true, "users.signUp() Error", new Error('Error While Login'), '');
                                    next(errorResult);
                                }
                            } else {
                                await header.rollback();
                                return res.status(401).json({
                                    message: 'Unable to Sign JWT',
                                    error: signJWTResult.error
                                });
                            }
                        } else {
                            await header.rollback();
                            let errorResult = new ResultError(400, true, "users.signUp() Error", new Error('Error While Inserting Data'), '');
                            next(errorResult);
                        }
                    } else {
                        await header.rollback();
                        let errorResult = new ResultError(400, true, "users.signUp() Error", new Error('Error While Inserting Data'), '');
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
    } catch (error) {

    }
};

const getMasterData = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Get Master Data');
        let result: any;
        // let sql = "CALL getMasterData()";
        // let masterData = await header.query(sql);
        let sql1 = `SELECT * FROM occupation WHERE isActive = 1 AND isDelete = 0;`;
        let result1 = await header.query(sql1);
        let sql2 = `SELECT * FROM education WHERE isActive = 1 AND isDelete = 0;`;
        let result2 = await header.query(sql2);
        let sql3 = `SELECT * FROM maritalstatus WHERE isActive = 1 AND isDelete = 0;`;
        let result3 = await header.query(sql3);
        let sql4 = `SELECT * FROM religion WHERE isActive = 1 AND isDelete = 0`;
        let result4 = await header.query(sql4);
        let sql5 = `SELECT * FROM community WHERE isActive = 1 AND isDelete = 0;`;
        let result5 = await header.query(sql5);
        let sql6 = `SELECT * FROM subcommunity WHERE isActive = 1 AND isDelete = 0;`;
        let result6 = await header.query(sql6);
        let sql7 = `SELECT * FROM diet WHERE isActive = 1 AND isDelete = 0;`;
        let result7 = await header.query(sql7);
        let sql8 = `SELECT * FROM height WHERE isActive = 1 AND isDelete = 0 order by name;`;
        let result8 = await header.query(sql8);
        let sql9 = `SELECT * FROM annualincome WHERE isActive = 1 AND isDelete = 0;`;
        let result9 = await header.query(sql9);
        let sql10 = `SELECT * FROM employmenttype WHERE isActive = 1 AND isDelete = 0;`;
        let result10 = await header.query(sql10);
        let sql11 = `SELECT * FROM documenttype WHERE isActive = 1 AND isDelete = 0;`;
        let result11 = await header.query(sql11);
        let sql12 = `SELECT * FROM profilefor WHERE isActive = 1 AND isDelete = 0;`;
        let result12 = await header.query(sql12);
        let sql13 = `SELECT * FROM weight WHERE isActive = 1 AND isDelete = 0 order by name;`
        let result13 = await header.query(sql13);


        // if (masterData && masterData.length > 0) {
        let minAge = await header.query(`SELECT min(DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0) as minAge
                                            FROM users u
                                            LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                                            LEFT JOIN userroles ur ON ur.userId = u.id
                                            WHERE ur.roleId = 2 `);
        let maxAge = await header.query(`SELECT max(DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0) as maxAge
                                            FROM users u
                                            LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                                            LEFT JOIN userroles ur ON ur.userId = u.id
                                            WHERE ur.roleId = 2`);
        let ageList = [];
        for (let i = 18; i <= 60; i++) {
            ageList.push(i)
        }
        let cityName = await header.query(`select (cityName) FROM addresses where cityName is not null or cityName !='' group by cityName  having  cityName !=''`)
        result = {
            "occupation": result1,
            "education": result2,
            "maritalStatus": result3,
            "religion": result4,
            "community": result5,
            "subCommunity": result6,
            "diet": result7,
            "height": result8,
            "annualIncome": result9,
            "employmentType": result10,
            "maxAge": maxAge[0].maxAge,
            "minAge": minAge[0].minAge,
            "ageList": ageList,
            "cityName": cityName,
            "documentType": result11,
            "profileFor": result12,
            "weight": result13,
        }
        let successResult = new ResultSuccess(200, true, 'Get Master Data Successfully', result, 1, '');
        return res.status(200).send(successResult);
        // } else {
        //     let errorResult = new ResultError(400, true, 'Data Not Available', new Error('Data Not Available'), '');
        //     next(errorResult);
        // }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'users.getUsers() Exception', error, '');
        next(errorResult);
    }
}

const getAllUsers = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Users');
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) {
            let currentUser = authorizationResult.currentUser;
            let userId = currentUser.id;
            let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
            let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
            let sql = `SELECT  u.id, u.firstName, u.middleName, u.lastName, u.gender, u.contactNo, u.email, img.imageUrl ,
                u.id IN (select proposalUserId from userproposals where userId = ` + userId + `) as isProposed,
                u.id IN (select favUserId from userfavourites where userId = ` + userId + `) as isFavourite
                 FROM users u
                LEFT JOIN userroles ur ON ur.userId = u.id
                LEFT JOIN images img ON img.id = u.imageId
                WHERE u.isDelete = 0 ANd ur.roleId = 2 AND u.id != ` + userId + ` AND
                u.id NOT IN (select userBlockId from userblock where userId = ` + userId + `) AND
                u.id NOT IN (select userId from userblock where userBlockId = ` + userId + `)
                and u.id NOT IN (select blockRequestUserId from userblockrequest where status = true AND userId = ` + userId + `)
                AND u.isDisable = 0
                 group by u.id`;
            if (startIndex != null && fetchRecord != null) {
                sql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
            }
            let result = await header.query(sql);
            if (result && result.length > 0) {
                let successResult = new ResultSuccess(200, true, 'Get Users Successfully', result, result.length, authorizationResult.token);
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
        let errorResult = new ResultError(500, true, 'users.getUsers() Exception', error, '');
        next(errorResult);
    }
};

const viewUserDetail = async (req: Request, res: Response, next: NextFunction) => {
    try {
        await header.beginTransaction();
        logging.info(NAMESPACE, 'Getting User Detail');
        let requiredFields = ['id'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let currentUser = authorizationResult.currentUser;
                let userId = currentUser ? currentUser.id : 0;

                let sql = `SELECT u.id, udd.fcmToken, u.firstName, u.middleName, u.lastName, u.gender, u.email, u.contactNo
                , upd.birthDate, upd.languages, upd.eyeColor, upd.expectation
                , upd.aboutMe, upd.companyName, upd.businessName, upd.weight, upd.profileForId, pf.name as profileForName
                , img.imageUrl, r.name as religion, ms.name as maritalStatus, c.name as community, o.name as occupation, e.name as education
                , sc.name as subCommunity, ai.value as annualIncome, d.name as diet, h.name as height
                , addr.addressLine1, addr.addressLine2, addr.pincode, addr.cityId, addr.districtId, addr.stateId, addr.countryId
                , ct.name as cityName, s.name as stateName, di.name as districtName, co.name as countryName
                , em.name as employmentType, DATE_FORMAT(FROM_DAYS(DATEDIFF(now(),upd.birthDate)), '%Y')+0 AS age
                , u.id IN (select favUserId from userfavourites where userId = `+ req.body.id + ` OR userId = ` + userId + `) as isFavourite
                , IF((select COUNT(id) from userproposals where (userId = ` + userId + ` AND proposalUserId = ` + req.body.id + `) OR (proposalUserId = ` + userId + ` AND userId = ` + req.body.id + `)) > 0,true,false) as isProposed
                , addr.latitude, addr.longitude
                FROM users u
                LEFT JOIN userroles ur ON ur.userId = u.id
                LEFT JOIN images img ON img.id = u.imageId
                LEFT JOIN userpersonaldetail upd ON upd.userId = u.id
                LEFT JOIN userdevicedetail udd ON udd.userId = u.id
                LEFT JOIN religion r ON r.id = upd.religionId
                LEFT JOIN maritalstatus ms ON ms.id = upd.maritalStatusId
                LEFT JOIN community c ON c.id = upd.communityId
                LEFT JOIN occupation o ON o.id = upd.occupationId
                LEFT JOIN education e ON e.id = upd.educationId
                LEFT JOIN subcommunity sc ON sc.id = upd.subCommunityId
                LEFT JOIN annualincome ai ON ai.id = upd.annualIncomeId
                LEFT JOIN diet d ON d.id = upd.dietId
                LEFT JOIN height h ON h.id = upd.heightId
                LEFT JOIN addresses addr ON addr.id = upd.addressId
                LEFT JOIN countries co ON co.id = addr.countryId
                LEFT JOIN state s ON s.id = addr.stateId
                LEFT JOIN districts di ON di.id = addr.districtId
                LEFT JOIN cities ct ON ct.id = addr.cityId
                LEFT JOIN employmenttype em ON em.id = upd.employmenttypeId
                LEFT JOIN profilefor pf ON pf.id = upd.profileForId

                 WHERE ur.roleId = 2 AND u.id = ` + req.body.id;
                let result = await header.query(sql);
                if (result && result.length > 0) {
                    // sql = `SELECT up.packageId,p.name as packageName,up.packageDurationId,up.startDate,up.endDate,up.netAmount,pay.paymentMode
                    // ,t.value   FROM  userpackage up
                    // LEFT JOIN package p on p.id= up.packageId
                    // LEFT join payment pay on pay.id= up.paymentId
                    // left join packageduration pd on pd.packageId = up.packageId
                    // left join timeduration t on t.id = pd.timeDurationId
                    // WHERE up.userId = `+ req.body.id + ` order by up.createdDate desc;`
                    // let userPackage = await header.query(sql);
                    // let packages = userPackage[0]
                    // // result[0].packages = packages
                    // // console.log(result[0].packages )
                    // if (packages) {
                    //     let packageFacility = await header.query(`SELECT  pff.name  FROM packagefacility pf
                    //         LEFT JOIN premiumfacility pff ON pff.id = pf.premiumFacilityId
                    //          WHERE pf.packageId = ` + packages.packageId);
                    //     packages.packageFacility = packageFacility;

                    //     result[0].userPackage = packages
                    // }
                    if (authorizationResult.token == '') {
                        let authorizationHeader = req.headers['authorization'];
                        let token: any = authorizationHeader?.split(' ')[1];
                        authorizationResult.token = token;
                    }

                    for (let i = 0; i < result.length; i++) {
                        result[i].isVerifiedProfile = false;
                        let isVerified = true;

                        let docVerifiedSql = `SELECT ud.*, dt.name as documentTypeName FROM userdocument ud INNER JOIN documenttype dt ON dt.id = ud.documentTypeId WHERE ud.userId =` + result[i].id;
                        let docVerifiedResult = await header.query(docVerifiedSql);
                        result[i].userDocuments = docVerifiedResult;
                        if (docVerifiedResult && docVerifiedResult.length > 0) {
                            for (let j = 0; j < docVerifiedResult.length; j++) {
                                if (docVerifiedResult[j].isRequired && !docVerifiedResult[j].isVerified) {
                                    isVerified = false;
                                }
                            }
                        } else {
                            isVerified = false;
                        }
                        result[i].isVerifiedProfile = isVerified;

                        let getUserAuthSql = `SELECT * FROM userauthdata WHERE userId = ` + result[i].id;
                        let getUserAuthResult = await header.query(getUserAuthSql)
                        result[i].isOAuth = (getUserAuthResult && getUserAuthResult.length > 0) ? true : false;
                        result[i].isAppleLogin = (getUserAuthResult && getUserAuthResult.length > 0 && getUserAuthResult[0].authProviderId == 3) ? true : false;

                        result[i].userWalletAmount = 0;
                        let getUserWalletSql = `SELECT * FROM userwallets WHERE userId = ` + result[i].id;
                        let getUserWalletResult = await header.query(getUserWalletSql);
                        if (getUserWalletResult && getUserWalletResult.length > 0) {
                            result[i].userWalletAmount = getUserWalletResult[0].amount
                        }

                        // result[i].userPackage = null;
                        // let packageSql = `SELECT up.*, p.name as packageName, td.id as timeDurationId, td.value FROM userpackage up
                        // LEFT JOIN package p ON p.id = up.packageId
                        // LEFT JOIN packageduration pd ON pd.id = up.packageDurationId
                        // LEFT JOIN timeduration td ON td.id = pd.timeDurationId
                        //     WHERE up.userId = ` + result[i].id + ` AND up.isActive=true AND up.isDelete = false AND DATE(up.startDate) <= DATE(CURRENT_TIMESTAMP()) AND DATE(up.endDate) >= DATE(CURRENT_TIMESTAMP()) order by p.weightage DESC LIMIT 1`;
                        // let packageResult = await header.query(packageSql);
                        // if (packageResult && packageResult.length > 0) {
                        //     result[i].userPackage = packageResult[0];

                        //     let packageFacility = await header.query(`SELECT  pff.name  FROM packagefacility pf
                        //     LEFT JOIN premiumfacility pff ON pff.id = pf.premiumFacilityId
                        //      WHERE pf.packageId = ` + result[i].userPackage.packageId);
                        //     result[i].userPackage.packageFacility = packageFacility;
                        // }

                        let userPackages = `SELECT up.*, p.name as packageName, td.id as timeDurationId, td.value, p.weightage FROM userpackage up
                                            LEFT JOIN package p ON p.id = up.packageId
                                            LEFT JOIN packageduration pd ON pd.id = up.packageDurationId
                                            LEFT JOIN timeduration td ON td.id = pd.timeDurationId
                                            WHERE up.userId = ` + result[i].id + ` AND DATE(up.startDate) <= DATE(CURRENT_TIMESTAMP()) AND DATE(up.endDate) >= DATE(CURRENT_TIMESTAMP())
                                            order by p.weightage DESC`;
                        let userPackage = await header.query(userPackages);
                        if (userPackage && userPackage.length > 0) {
                            for (let k = 0; k < userPackage.length; k++) {
                                let packageFacility = await header.query(`SELECT pf.*, pff.name FROM packagefacility pf
                                                    LEFT JOIN premiumfacility pff ON pff.id = pf.premiumFacilityId
                                                     WHERE pf.packageId = ` + userPackage[k].packageId);
                                userPackage[k].packageFacility = packageFacility;
                            }
                        }
                        result[i].userPackage = userPackage[0];
                    }

                    if (userId) {
                        if (userId != req.body.id) {
                            result[0].totalView = 0;
                            result[0].todayView = 0;
                            //notification send to req.body.id
                            let insertProfileHistorySql = `INSERT INTO userviewprofilehistories(userId, viewProfileByUserId, transactionDate, createdBy, modifiedBy) 
                        VALUES(`+ req.body.id + `,` + userId + `, CURRENT_TIMESTAMP(),` + userId + `,` + userId + `)`;
                            let insertProfileHistoryResult = await header.query(insertProfileHistorySql);
                            if (insertProfileHistoryResult && insertProfileHistoryResult.insertId) {
                                let fcmToken;
                                let customerFcmSql = "SELECT fcmToken FROM userdevicedetail WHERE userId = " + req.body.id + " ORDER BY id DESC LIMIT 1";
                                let customerFcmResult = await header.query(customerFcmSql);
                                if (customerFcmResult && customerFcmResult.length > 0) {
                                    fcmToken = customerFcmResult[0].fcmToken;
                                }

                                let check = `SELECT uf.id as userflagId , ufv.userId FROM userflags uf
                            LEFT JOIN userflagvalues ufv ON ufv.userId = `+ req.body.id + `
                            WHERE uf.flagName = 'pushNotification' AND ufv.userFlagValue = 1`;
                                let checkResult = await header.query(check);
                                if (checkResult && checkResult.length > 0) {
                                    if (fcmToken) {
                                        let title = "View Profile";
                                        let userSql = `SELECT * FROM users WHERE id = ` + userId;
                                        let userResult = await header.query(userSql);
                                        let description = (userResult && userResult.length > 0) ? (userResult[0].firstName + " " + userResult[0].lastName + " view your profile") : "";

                                        let notificationRes = await notificationContainer.sendMultipleNotification([fcmToken], req.body.id, title, description, '', null, null, 1);
                                        let notificationSql = `INSERT INTO usernotifications(userId, title, message, bodyJson, imageUrl, createdBy, modifiedBy)
                                     VALUES(` + req.body.id + `,'` + title + `', '` + description + `', null, null, ` + authorizationResult.currentUser.id + `, ` + authorizationResult.currentUser.id + `)`
                                        let notificationresult = await header.query(notificationSql);
                                        if (notificationresult && notificationresult.insertId > 0) {
                                            await header.commit();

                                            let successResult = new ResultSuccess(200, true, 'Get Users Detail Successfully', result, result.length, authorizationResult.token);
                                            return res.status(200).send(successResult);
                                        } else {
                                            await header.rollback();
                                            let errorResult = new ResultError(400, true, "favourites.addRemoveFavourite() Error", new Error('Error While Updating Data'), '');
                                            next(errorResult);
                                        }
                                    } else {
                                        await header.commit();

                                        let successResult = new ResultSuccess(200, true, 'Get Users Detail Successfully', result, result.length, authorizationResult.token);
                                        return res.status(200).send(successResult);
                                    }
                                } else {
                                    await header.commit();

                                    let successResult = new ResultSuccess(200, true, 'Get Users Detail Successfully', result, result.length, authorizationResult.token);
                                    return res.status(200).send(successResult);
                                }
                            } else {
                                await header.rollback();
                                let errorResult = new ResultError(400, true, 'Error While Insert Data', new Error('Error While Insert Data'), '');
                                next(errorResult);
                            }
                        } else {
                            // get today and total view count
                            result[0].totalView = 0;
                            result[0].todayView = 0;
                            let totalViewSql = `SELECT COUNT(id) as totalView FROM userviewprofilehistories WHERE userId = ` + userId;
                            let totalViewResult = await header.query(totalViewSql);
                            if (totalViewResult && totalViewResult.length > 0) {
                                result[0].totalView = totalViewResult[0].totalView
                            }
                            let todayViewSql = `SELECT COUNT(id) as totalView FROM userviewprofilehistories WHERE userId = ` + userId + ` AND DATE(transactionDate) = DATE(CURRENT_TIMESTAMP())`;
                            let todayViewResult = await header.query(todayViewSql);
                            if (todayViewResult && todayViewResult.length > 0) {
                                result[0].todayView = todayViewResult[0].totalView
                            }
                            let successResult = new ResultSuccess(200, true, 'Get Users Detail Successfully', result, result.length, authorizationResult.token);
                            return res.status(200).send(successResult);
                        }
                    } else {
                        result[0].totalView = 0;
                        result[0].todayView = 0;
                        let successResult = new ResultSuccess(200, true, 'Get Users Detail Successfully', result, result.length, authorizationResult.token);
                        return res.status(200).send(successResult);
                    }
                } else {
                    let errorResult = new ResultError(400, true, 'Data Not Available', new Error('Data Not Available'), '');
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
        let errorResult = new ResultError(500, true, 'users.getUserDetail() Exception', error, '');
        next(errorResult);
    }
};

const updateUserProfilePic = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Updating Users');
        let requiredFields = ['id', 'image'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let result;
                let imageId;
                req.body.userId = req.body.id;
                try {
                    let checkSql = `SELECT * FROM users WHERE id = ` + req.body.userId;
                    let checkResult = await header.query(checkSql);
                    if (checkResult && checkResult.length) {
                        let oldImageId = checkResult[0].imageId;
                        if (oldImageId) {
                            if (req.body.image && req.body.image.indexOf('content') == -1) {
                                let sql = `INSERT INTO images(createdBy, modifiedBy) VALUES (` + req.body.userId + `,` + req.body.userId + `)`;
                                result = await header.query(sql);
                                if (result.affectedRows > 0) {
                                    imageId = result.insertId;

                                    let image = req.body.image;
                                    let data = image.split(',');
                                    if (data && data.length > 1) {
                                        image = image.split(',')[1]
                                    }

                                    let dir = './content';
                                    if (!fs.existsSync(dir)) {
                                        fs.mkdirSync(dir);
                                    }

                                    let dir1 = './content/user';
                                    if (!fs.existsSync(dir1)) {
                                        fs.mkdirSync(dir1);
                                    }

                                    let dir2 = './content/user/' + req.body.userId;
                                    if (!fs.existsSync(dir2)) {
                                        fs.mkdirSync(dir2);
                                    }
                                    const fileContentsUser = new Buffer(image, 'base64')
                                    let imgPath = "./content/user/" + req.body.userId + "/" + imageId + "-realImg.jpeg";

                                    fs.writeFileSync(imgPath, fileContentsUser, (err: any) => {
                                        if (err)
                                            return console.error(err)
                                        console.log('file saved imagePath')
                                    });
                                    let imagePath = "./content/user/" + req.body.userId + "/" + imageId + ".jpeg";
                                    // sharp(imgPath).resize({
                                    //     height: 100,
                                    //     width: 100
                                    // }).toFile(imagePath)
                                    //     .then(function (newFileInfo: any) {
                                    //         console.log(newFileInfo);
                                    //     });
                                    await Jimp.read(imgPath)
                                        .then(async (lenna: any) => {
                                            // return lenna
                                            //     .resize(100, 100) // resize
                                            //     // .quality(60) // set JPEG quality
                                            //     // .greyscale() // set greyscale
                                            //     // .write("lena-small-bw.jpg"); // save
                                            //     .write(imagePath);
                                            let data = lenna
                                                //.resize(100, 100) // resize
                                                // .quality(60) // set JPEG quality
                                                // .greyscale() // set greyscale
                                                // .write("lena-small-bw.jpg"); // save
                                                .write(imagePath);


                                            const image_act = await Jimp.read(imagePath);
                                            const watermark = await Jimp.read('./content/systemflag/watermarkImage/watermarkImage.jpeg');
                                            watermark.resize(image_act.getWidth() / 2, Jimp.AUTO);
                                            const x = (image_act.getWidth() - watermark.getWidth()) / 2;
                                            const y = (image_act.getHeight() - (watermark.getHeight() * 2));

                                            image_act.composite(watermark, x, y, {
                                                mode: Jimp.BLEND_SOURCE_OVER,
                                                opacitySource: 0.5, // Adjust the opacity of the watermark
                                            });
                                            //imagePath = "./content/notification/" + notificationId + ".jpeg";
                                            await image_act.writeAsync(imagePath);
                                            return data;
                                        })
                                        .catch((err: any) => {
                                            console.error(err);
                                        });
                                    let updateimagePathSql = `UPDATE images SET imageUrl='` + imagePath.substring(2) + `' WHERE id=` + imageId;
                                    let updateimagePathResult = await header.query(updateimagePathSql);
                                    if (updateimagePathResult && updateimagePathResult.affectedRows > 0) {
                                        let addUserImageId = `UPDATE users SET imageId = ` + imageId + ` WHERE id = ` + req.body.userId;
                                        result = await header.query(addUserImageId);
                                        if (result && result.affectedRows > 0) {
                                            let getOldImageSql = `SELECT * FROM images where Id = ` + oldImageId;
                                            let getOldImageResult = await header.query(getOldImageSql);
                                            if (getOldImageResult && getOldImageResult.length > 0) {
                                                let delSql = `DELETE FROM images where Id = ` + oldImageId;
                                                let delResult = await header.query(delSql);
                                                if (delResult && delResult.affectedRows > 0) {
                                                    if (getOldImageResult[0].imageUrl) {
                                                        let imagePath = "./" + getOldImageResult[0].imageUrl;
                                                        if (fs.existsSync(imagePath)) {
                                                            fs.unlink(imagePath, (err: any) => {
                                                                if (err) throw err;
                                                                console.log(imagePath + ' was deleted');
                                                            });
                                                        }
                                                        let realImg = "./" + getOldImageResult[0].imageUrl.split(".")[0] + "-realImg." + getOldImageResult[0].imageUrl.split(".")[1];
                                                        if (fs.existsSync(realImg)) {
                                                            fs.unlink(realImg, (err: any) => {
                                                                if (err) throw err;
                                                                console.log(realImg + ' was deleted');
                                                            });
                                                        }
                                                    }
                                                    // if (fs.existsSync("./content/user/" + req.body.userId + "/" + oldImageId + ".jpeg")) {
                                                    //     fs.unlink("./content/user/" + req.body.userId + "/" + oldImageId + ".jpeg", (err: any) => {
                                                    //         if (err) throw err;
                                                    //         console.log(imagePath + ' was deleted');
                                                    //     });
                                                    // }
                                                    // if (fs.existsSync("./content/user/" + req.body.userId + "/" + oldImageId + "-realImg.jpeg")) {
                                                    //     fs.unlink("./content/user/" + req.body.userId + "/" + oldImageId + "-realImg.jpeg", (err: any) => {
                                                    //         if (err) throw err;
                                                    //         console.log(imagePath + ' was deleted');
                                                    //     });
                                                    // }
                                                    //let userSql = `SELECT u.*, img.imageUrl FROM users u LEFT JOIN images img ON img.id = u.imageId WHERE u.id = ` + req.body.userId;
                                                    let userSql = `SELECT img.imageUrl FROM users u LEFT JOIN images img ON img.id = u.imageId WHERE u.id = ` + req.body.userId;
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
                                        }
                                    } else {
                                        let errorResult = new ResultError(400, true, "users.updateUserProfilePic() Error", new Error('Error While Updating Profile Pic'), '');
                                        next(errorResult);
                                    }
                                } else {
                                    let errorResult = new ResultError(400, true, "users.updateUserProfilePic() Error", new Error('Error While Updating Profile Pic'), '');
                                    next(errorResult);
                                }
                            } else {
                                let addUserImageId = `UPDATE users SET imageId = ` + oldImageId + ` WHERE id = ` + req.body.userId;
                                result = await header.query(addUserImageId);
                                //let userSql = `SELECT u.*, img.imageUrl FROM users u LEFT JOIN images img ON img.id = u.imageId WHERE u.id = ` + req.body.userId;
                                let userSql = `SELECT img.imageUrl FROM users u LEFT JOIN images img ON img.id = u.imageId WHERE u.id = ` + req.body.userId;
                                let userResult = await header.query(userSql);
                                if (userResult && userResult.length > 0) {
                                    let successResult = new ResultSuccess(200, true, 'Update User Profile Pic', userResult, userResult.length, authorizationResult.token);
                                    return res.status(200).send(successResult);
                                } else {
                                    let errorResult = new ResultError(400, true, "users.updateUserProfilePic() Error", new Error('Error While Updating Data'), '');
                                    next(errorResult);
                                }
                            }
                        } else {
                            if (req.body.image && req.body.image.indexOf('content') == -1) {
                                let sql = `INSERT INTO images(createdBy, modifiedBy) VALUES (` + req.body.userId + `,` + req.body.userId + `)`;
                                result = await header.query(sql);
                                if (result.affectedRows > 0) {
                                    imageId = result.insertId;

                                    let image = req.body.image;
                                    let data = image.split(',');
                                    if (data && data.length > 1) {
                                        image = image.split(',')[1]
                                    }

                                    let dir = './content';
                                    if (!fs.existsSync(dir)) {
                                        fs.mkdirSync(dir);
                                    }

                                    let dir1 = './content/user';
                                    if (!fs.existsSync(dir1)) {
                                        fs.mkdirSync(dir1);
                                    }

                                    let dir2 = './content/user/' + req.body.userId;
                                    if (!fs.existsSync(dir2)) {
                                        fs.mkdirSync(dir2);
                                    }
                                    const fileContentsUser = new Buffer(image, 'base64')
                                    let imgPath = "./content/user/" + req.body.userId + "/" + imageId + "-realImg.jpeg";

                                    fs.writeFileSync(imgPath, fileContentsUser, (err: any) => {
                                        if (err)
                                            return console.error(err)
                                        console.log('file saved imagePath')
                                    });
                                    let imagePath = "./content/user/" + req.body.userId + "/" + imageId + ".jpeg";
                                    // sharp(imgPath).resize({
                                    //     height: 100,
                                    //     width: 100
                                    // }).toFile(imagePath)
                                    //     .then(function (newFileInfo: any) {
                                    //         console.log(newFileInfo);
                                    //     });
                                    await Jimp.read(imgPath)
                                        .then(async (lenna: any) => {
                                            // return lenna
                                            //     .resize(100, 100) // resize
                                            //     // .quality(60) // set JPEG quality
                                            //     // .greyscale() // set greyscale
                                            //     // .write("lena-small-bw.jpg"); // save
                                            //     .write(imagePath);
                                            let data = lenna
                                                //.resize(100, 100) // resize
                                                // .quality(60) // set JPEG quality
                                                // .greyscale() // set greyscale
                                                // .write("lena-small-bw.jpg"); // save
                                                .write(imagePath);


                                            const image_act = await Jimp.read(imagePath);
                                            const watermark = await Jimp.read('./content/systemflag/watermarkImage/watermarkImage.jpeg');
                                            watermark.resize(image_act.getWidth() / 2, Jimp.AUTO);
                                            const x = (image_act.getWidth() - watermark.getWidth()) / 2;
                                            const y = (image_act.getHeight() - (watermark.getHeight() * 2));

                                            image_act.composite(watermark, x, y, {
                                                mode: Jimp.BLEND_SOURCE_OVER,
                                                opacitySource: 0.5, // Adjust the opacity of the watermark
                                            });
                                            //imagePath = "./content/notification/" + notificationId + ".jpeg";
                                            await image_act.writeAsync(imagePath);
                                            return data;
                                        })
                                        .catch((err: any) => {
                                            console.error(err);
                                        });
                                    let updateimagePathSql = `UPDATE images SET imageUrl='` + imagePath.substring(2) + `' WHERE id=` + imageId;
                                    let updateimagePathResult = await header.query(updateimagePathSql);
                                    if (updateimagePathResult && updateimagePathResult.affectedRows > 0) {
                                        let addUserImageId = `UPDATE users SET imageId = ` + imageId + ` WHERE id = ` + req.body.userId;
                                        result = await header.query(addUserImageId);
                                        //let userSql = `SELECT u.*, img.imageUrl FROM users u  LEFT JOIN images img ON img.id = u.imageId                                        WHERE u.id = ` + req.body.userId;
                                        let userSql = `SELECT img.imageUrl FROM users u LEFT JOIN images img ON img.id = u.imageId WHERE u.id = ` + req.body.userId;
                                        let userResult = await header.query(userSql);
                                        if (userResult && userResult.length > 0) {
                                            let successResult = new ResultSuccess(200, true, 'Update User Profile Pic', userResult, userResult.length, authorizationResult.token);
                                            return res.status(200).send(successResult);
                                        } else {
                                            let errorResult = new ResultError(400, true, "users.updateUserProfilePic() Error", new Error('Error While Updating Profile Pic'), '');
                                            next(errorResult);
                                        }
                                    } else {
                                        let errorResult = new ResultError(400, true, "users.updateUserProfilePic() Error", new Error('Error While Updating Profile Pic'), '');
                                        next(errorResult);
                                    }
                                } else {
                                    let errorResult = new ResultError(400, true, "users.updateUserProfilePic() Error", new Error('Error While Updating Profile Pic'), '');
                                    next(errorResult);
                                }
                            } else {
                                let errorResult = new ResultError(400, true, "users.updateUserProfilePic() Error", new Error('Image Not Found'), '');
                                next(errorResult);
                            }
                        }
                    } else {
                        let errorResult = new ResultError(400, true, "users.updateUserProfilePic() Error", new Error('User Not Found'), '');
                        next(errorResult);
                    }
                } catch (err) {
                    let imagePath = "./content/user/" + req.body.userId + "/" + imageId + ".jpeg";
                    if (fs.existsSync(imagePath)) {
                        fs.unlink(imagePath, (err: any) => {
                            if (err) throw err;
                            console.log(imagePath + ' was deleted');
                        });
                    }
                    let dir = './content/user/' + req.body.userId;
                    if (fs.existsSync(dir)) {
                        fs.rmdir(dir, (err: any) => {
                            if (err) throw err;
                            console.log(dir + ' was deleted');
                        });
                    }
                    result = err;
                }
                return result;
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
        let errorResult = new ResultError(500, true, 'users.updateUserProfilePic() Exception', error, '');
        next(errorResult);
    }
};

const updateUserProfileDetail = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Updating Users');
        let requiredFields = ['id', 'firstName', 'lastName', 'email', 'gender', 'birthDate', 'addressLine1', 'pincode', 'religionId', 'communityId', 'maritalStatusId', 'occupationId', 'educationId', 'annualIncomeId', 'heightId', 'languages', 'employmentTypeId'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                await header.beginTransaction();
                let currentUser = authorizationResult.currentUser;
                let userId = currentUser.id;
                req.body.contactNo = req.body.contactNo ? req.body.contactNo : '';
                req.body.middleName = req.body.middleName ? req.body.middleName : '';
                req.body.countryName = req.body.countryName ? req.body.countryName : '';
                req.body.stateName = req.body.stateName ? req.body.stateName : '';
                req.body.cityName = req.body.cityName ? req.body.cityName : '';
                req.body.aboutMe = req.body.aboutMe ? req.body.aboutMe : '';
                req.body.expectation = req.body.expectation ? req.body.expectation : '';
                req.body.eyeColor = req.body.eyeColor ? req.body.eyeColor : '';
                let birthDate = req.body.birthDate ? new Date(req.body.birthDate) : '';
                let bDate = new Date(birthDate).getFullYear().toString() + '-' + ("0" + (new Date(birthDate).getMonth() + 1)).slice(-2) + '-' + ("0" + new Date(birthDate).getDate()).slice(-2) + ' ' + ("0" + (new Date(birthDate).getHours())).slice(-2) + ':' + ("0" + (new Date(birthDate).getMinutes())).slice(-2) + ':' + ("0" + (new Date(birthDate).getSeconds())).slice(-2);

                let checkSql = `SELECT * FROM users WHERE email = '` + req.body.email + `' AND id != ` + req.body.id;
                let checkResult = await header.query(checkSql);
                if (checkResult && checkResult.length > 0) {
                    await header.rollback();
                    let message = 'Email Already Inserted';
                    return res.status(200).send(message);
                    // let errorResult = new ResultError(203, true, message, new Error(message), '');
                    // next(errorResult);

                } else {
                    let result;
                    let sql = `UPDATE users SET firstName = '` + req.body.firstName + `', middleName = '` + req.body.middleName + `', lastName = '` + req.body.lastName + `'
                , contactNo = '` + req.body.contactNo + `',email = '` + req.body.email + `',gender = '` + req.body.gender + `' WHERE id = ` + req.body.id + ``;
                    result = await header.query(sql);
                    if (result && result.affectedRows > 0) {
                        if (req.body.documents && req.body.documents.length > 0) {
                            for (let i = 0; i < req.body.documents.length; i++) {
                                if (req.body.documents[i].isRequired) {
                                    if (!req.body.documents[i].documentUrl) {
                                        let errorResult = new ResultError(400, true, "Document is Required", new Error('Document is Required'), '');
                                        next(errorResult);
                                        return errorResult;
                                    }
                                }
                                if (req.body.documents[i].documentUrl) {
                                    if (req.body.documents[i].id) {
                                        if (req.body.documents[i].documentUrl && req.body.documents[i].documentUrl.indexOf('content') == -1) {
                                            let userDocumentId = req.body.documents[i].id;
                                            let oldDocummentSql = `SELECT * FROM userdocument WHERE id = ` + userDocumentId;
                                            let oldDocummentResult = await header.query(oldDocummentSql);

                                            let image = req.body.documents[i].documentUrl;
                                            let data = image.split(',');
                                            if (data && data.length > 1) {
                                                image = image.split(',')[1]
                                            }

                                            let dir = './content';
                                            if (!fs.existsSync(dir)) {
                                                fs.mkdirSync(dir);
                                            }

                                            let dir1 = './content/userDocument';
                                            if (!fs.existsSync(dir1)) {
                                                fs.mkdirSync(dir1);
                                            }

                                            let dir2 = './content/userDocument/' + req.body.id;
                                            if (!fs.existsSync(dir2)) {
                                                fs.mkdirSync(dir2);
                                            }
                                            const fileContentsUser = new Buffer(image, 'base64')
                                            let imgPath = "./content/userDocument/" + req.body.id + "/" + userDocumentId + "-realImg.jpeg";

                                            fs.writeFileSync(imgPath, fileContentsUser, (err: any) => {
                                                if (err)
                                                    return console.error(err)
                                                console.log('file saved imagePath')
                                            });
                                            let imagePath = "./content/userDocument/" + req.body.id + "/" + userDocumentId + ".jpeg";
                                            await Jimp.read(imgPath)
                                                .then(async (lenna: any) => {
                                                    // return lenna
                                                    //     //.resize(100, 100) // resize
                                                    //     .quality(60) // set JPEG quality
                                                    //     // .greyscale() // set greyscale
                                                    //     // .write("lena-small-bw.jpg"); // save
                                                    //     .write(imagePath);
                                                    let data = lenna
                                                        //.resize(100, 100) // resize
                                                        // .quality(60) // set JPEG quality
                                                        // .greyscale() // set greyscale
                                                        // .write("lena-small-bw.jpg"); // save
                                                        .write(imagePath);


                                                    const image_act = await Jimp.read(imagePath);
                                                    const watermark = await Jimp.read('./content/systemflag/watermarkImage/watermarkImage.jpeg');
                                                    watermark.resize(image_act.getWidth() / 2, Jimp.AUTO);
                                                    const x = (image_act.getWidth() - watermark.getWidth()) / 2;
                                                    const y = (image_act.getHeight() - (watermark.getHeight() * 2));

                                                    image_act.composite(watermark, x, y, {
                                                        mode: Jimp.BLEND_SOURCE_OVER,
                                                        opacitySource: 0.5, // Adjust the opacity of the watermark
                                                    });
                                                    //imagePath = "./content/notification/" + notificationId + ".jpeg";
                                                    await image_act.writeAsync(imagePath);
                                                    return data;
                                                })
                                                .catch((err: any) => {
                                                    console.error(err);
                                                });
                                            let updateimagePathSql = `UPDATE userdocument SET documentUrl='` + imagePath.substring(2) + `' WHERE id=` + userDocumentId;
                                            let updateimagePathResult = await header.query(updateimagePathSql);
                                            if (updateimagePathResult && updateimagePathResult.affectedRows > 0) {
                                                // if (oldDocummentResult && oldDocummentResult.length > 0) {
                                                //     for (let d = 0; d < oldDocummentResult.length; d++) {
                                                //         if (oldDocummentResult[d].documentUrl) {
                                                //             let oldUrl = oldDocummentResult[d].documentUrl;
                                                //             let imagePath = "./" + oldUrl;
                                                //             if (fs.existsSync(imagePath)) {
                                                //                 fs.unlink(imagePath, (err: any) => {
                                                //                     if (err) throw err;
                                                //                     console.log(imagePath + ' was deleted');
                                                //                 });
                                                //             }

                                                //             let realImg = "./" + oldUrl.split(".")[0] + "-realImg." + oldUrl.split(".")[1];
                                                //             if (fs.existsSync(realImg)) {
                                                //                 fs.unlink(realImg, (err: any) => {
                                                //                     if (err) throw err;
                                                //                     console.log(realImg + ' was deleted');
                                                //                 });
                                                //             }
                                                //         }
                                                //     }
                                                // }
                                            } else {
                                                let errorResult = new ResultError(400, true, "users.updateUserProfilePic() Error", new Error('Error While Updating Profile Pic'), '');
                                                next(errorResult);
                                            }
                                        }
                                    } else {
                                        if (req.body.documents[i].documentUrl && req.body.documents[i].documentUrl.indexOf('content') == -1) {
                                            //let imageSql = `INSERT INTO images(createdBy, modifiedBy) VALUES (` + req.body.id + `,` + req.body.id + `)`;
                                            let userDocumentSql = `INSERT INTO userdocument(userId, documentTypeId, isVerified, isRequired, createdBy, modifiedBy) 
                                        VALUES(`+ req.body.id + `,` + req.body.documents[i].documentTypeId + `, 0, ` + req.body.documents[i].isRequired + `,` + req.body.id + `,` + req.body.id + `)`;
                                            result = await header.query(userDocumentSql);
                                            if (result.insertId) {
                                                let userDocumentId = result.insertId;

                                                let image = req.body.documents[i].documentUrl;
                                                let data = image.split(',');
                                                if (data && data.length > 1) {
                                                    image = image.split(',')[1]
                                                }

                                                let dir = './content';
                                                if (!fs.existsSync(dir)) {
                                                    fs.mkdirSync(dir);
                                                }

                                                let dir1 = './content/userDocument';
                                                if (!fs.existsSync(dir1)) {
                                                    fs.mkdirSync(dir1);
                                                }

                                                let dir2 = './content/userDocument/' + req.body.id;
                                                if (!fs.existsSync(dir2)) {
                                                    fs.mkdirSync(dir2);
                                                }
                                                const fileContentsUser = new Buffer(image, 'base64')
                                                let imgPath = "./content/userDocument/" + req.body.id + "/" + userDocumentId + "-realImg.jpeg";

                                                fs.writeFileSync(imgPath, fileContentsUser, (err: any) => {
                                                    if (err)
                                                        return console.error(err)
                                                    console.log('file saved imagePath')
                                                });
                                                let imagePath = "./content/userDocument/" + req.body.id + "/" + userDocumentId + ".jpeg";
                                                await Jimp.read(imgPath)
                                                    .then(async (lenna: any) => {
                                                        // return lenna
                                                        //     //.resize(100, 100) // resize
                                                        //     .quality(60) // set JPEG quality
                                                        //     // .greyscale() // set greyscale
                                                        //     // .write("lena-small-bw.jpg"); // save
                                                        //     .write(imagePath);
                                                        let data = lenna
                                                            //.resize(100, 100) // resize
                                                            // .quality(60) // set JPEG quality
                                                            // .greyscale() // set greyscale
                                                            // .write("lena-small-bw.jpg"); // save
                                                            .write(imagePath);


                                                        const image_act = await Jimp.read(imagePath);
                                                        const watermark = await Jimp.read('./content/systemflag/watermarkImage/watermarkImage.jpeg');
                                                        watermark.resize(image_act.getWidth() / 2, Jimp.AUTO);
                                                        const x = (image_act.getWidth() - watermark.getWidth()) / 2;
                                                        const y = (image_act.getHeight() - (watermark.getHeight() * 2));

                                                        image_act.composite(watermark, x, y, {
                                                            mode: Jimp.BLEND_SOURCE_OVER,
                                                            opacitySource: 0.5, // Adjust the opacity of the watermark
                                                        });
                                                        //imagePath = "./content/notification/" + notificationId + ".jpeg";
                                                        await image_act.writeAsync(imagePath);
                                                        return data;
                                                    })
                                                    .catch((err: any) => {
                                                        console.error(err);
                                                    });
                                                let updateimagePathSql = `UPDATE userdocument SET documentUrl='` + imagePath.substring(2) + `' WHERE id=` + userDocumentId;
                                                let updateimagePathResult = await header.query(updateimagePathSql);
                                                if (updateimagePathResult && updateimagePathResult.affectedRows > 0) {

                                                } else {
                                                    let errorResult = new ResultError(400, true, "users.updateUserProfilePic() Error", new Error('Error While Updating Profile Pic'), '');
                                                    next(errorResult);
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    if (req.body.documents[i].id) {
                                        let oldDocummentSql = `SELECT * FROM userdocument WHERE id = ` + req.body.documents[i].id;
                                        let oldDocummentResult = await header.query(oldDocummentSql);
                                        let updateimagePathSql = `DELETE FROM userdocument WHERE id=` + req.body.documents[i].id;
                                        let updateimagePathResult = await header.query(updateimagePathSql);
                                        if (updateimagePathResult && updateimagePathResult.affectedRows > 0) {
                                            if (oldDocummentResult && oldDocummentResult.length > 0) {
                                                for (let d = 0; d < oldDocummentResult.length; d++) {
                                                    if (oldDocummentResult[d].documentUrl) {
                                                        let oldUrl = oldDocummentResult[d].documentUrl;
                                                        let imagePath = "./" + oldUrl;
                                                        if (fs.existsSync(imagePath)) {
                                                            fs.unlink(imagePath, (err: any) => {
                                                                if (err) throw err;
                                                                console.log(imagePath + ' was deleted');
                                                            });
                                                        }

                                                        let realImg = "./" + oldUrl.split(".")[0] + "-realImg." + oldUrl.split(".")[1];
                                                        if (fs.existsSync(realImg)) {
                                                            fs.unlink(realImg, (err: any) => {
                                                                if (err) throw err;
                                                                console.log(realImg + ' was deleted');
                                                            });
                                                        }
                                                    }
                                                }
                                            }
                                        } else {
                                            let errorResult = new ResultError(400, true, "users.updateUserProfilePic() Error", new Error('Error While Updating Profile Pic'), '');
                                            next(errorResult);
                                        }
                                    }
                                }
                            }
                        }
                        let userPerDetailSql = `SELECT * FROM userpersonaldetail WHERE userId = ` + req.body.id + ``;
                        result = await header.query(userPerDetailSql);
                        if (result && result.length > 0) {
                            let userpersonaldetailId = result[0].id;
                            req.body.addressId = result[0].addressId;
                            req.body.birthDate = req.body.birthDate ? req.body.birthDate : '';
                            let updateAddSql = `UPDATE addresses SET addressLine1 = '` + req.body.addressLine1 + `', addressLine2 = '` + req.body.addressLine2 + `', pincode = '` + req.body.pincode + `'
                        , cityId = ` + (req.body.cityId ? req.body.cityId : null) + `, districtId = ` + (req.body.districtId ? req.body.districtId : null) + `
                        , stateId = ` + (req.body.stateId ? req.body.stateId : null) + `, countryId = ` + (req.body.countryId ? req.body.countryId : null) + `
                        , countryName = '` + req.body.countryName + `', stateName = '` + req.body.stateName + `', cityName = '` + req.body.cityName + `' 
                        , latitude = `+ (req.body.latitude ? req.body.latitude : null) + `, longitude = ` + (req.body.longitude ? req.body.longitude : null) + ` WHERE id = ` + req.body.addressId + ``;
                            let updateAddressResult = await header.query(updateAddSql);
                            if (updateAddressResult && updateAddressResult.affectedRows > 0) {
                                // let addressId = updateAddressResult[0].id;
                                let updateSql = `UPDATE userpersonaldetail SET addressId = ` + req.body.addressId + `, religionId = ` + req.body.religionId + `,communityId = ` + req.body.communityId + `,maritalStatusId = ` + req.body.maritalStatusId + `,occupationId = ` + req.body.occupationId + `,educationId = ` + req.body.educationId + `,subCommunityId = ` + req.body.subCommunityId + `,dietId = ` + req.body.dietId + `,annualIncomeId = ` + req.body.annualIncomeId + `,heightId = ` + req.body.heightId + `,birthDate = '` + bDate + `',languages = '` + req.body.languages + `',eyeColor = '` + req.body.eyeColor + `', businessName = '` + req.body.businessName + `', companyName = '` + req.body.companyName + `', employmentTypeId = ` + req.body.employmentTypeId + `, expectation = '` + req.body.expectation + `', aboutMe = '` + req.body.aboutMe + `'  WHERE id = ` + userpersonaldetailId + ``;
                                result = await header.query(updateSql);
                                if (result && result.affectedRows > 0) {
                                    let sql = `SELECT u.id, u.firstName, u.middleName, u.lastName, u.gender, u.email, u.contactNo
                                    , upd.birthDate, upd.languages, upd.eyeColor, upd.expectation, upd.aboutMe, upd.weight, upd.profileForId, pf.name as profileForName, img.imageUrl
                                , r.name as religion, ms.name as maritalStatus, c.name as community, o.name as occupation, e.name as education, sc.name as subCommunity, ai.value as annualIncome, d.name as diet, h.name as height
                                , addr.addressLine1, addr.addressLine2, addr.pincode, addr.cityId, addr.districtId, addr.stateId, addr.countryId
                                , cit.name as cityName, ds.name as districtName, st.name as stateName, cou.name as countryName
                                , em.name as employmentType, DATE_FORMAT(FROM_DAYS(DATEDIFF(now(),upd.birthDate)), '%Y')+0 AS age
                                , addr.latitude, addr.longitude
                                FROM users u
                                LEFT JOIN userroles ur ON ur.userId = u.id
                                LEFT JOIN images img ON img.id = u.imageId
                                LEFT JOIN userpersonaldetail upd ON upd.userId = u.id
                                LEFT JOIN religion r ON r.id = upd.religionId
                                LEFT JOIN maritalstatus ms ON ms.id = upd.maritalStatusId
                                LEFT JOIN community c ON c.id = upd.communityId
                                LEFT JOIN occupation o ON o.id = upd.occupationId
                                LEFT JOIN education e ON e.id = upd.educationId
                                LEFT JOIN subcommunity sc ON sc.id = upd.subCommunityId
                                LEFT JOIN annualincome ai ON ai.id = upd.annualIncomeId
                                LEFT JOIN diet d ON d.id = upd.dietId
                                LEFT JOIN height h ON h.id = upd.heightId
                                LEFT JOIN addresses addr ON addr.id = upd.addressId
                                LEFT JOIN cities cit ON addr.cityId = cit.id
                                LEFT JOIN districts ds ON addr.districtId = ds.id
                                LEFT JOIN state st ON addr.stateId = st.id
                                LEFT JOIN countries cou ON addr.countryId = cou.id
                                LEFT JOIN employmenttype em ON em.id = upd.employmenttypeId
                                LEFT JOIN profilefor pf ON pf.id = upd.profileForId
                                 WHERE ur.roleId = 2 AND u.id = ` + req.body.id;
                                    let result = await header.query(sql);

                                    if (result && result.length > 0) {
                                        result[0].isVerified = false;
                                        let isVerified = true;
                                        let documentsSql = `SELECT ud.*, dt.name as documentTypeName FROM userdocument ud INNER JOIN documenttype dt ON dt.id = ud.documentTypeId WHERE userId = ` + result[0].id;
                                        let documentsResult = await header.query(documentsSql);
                                        result[0].userDocuments = documentsResult;
                                        if (documentsResult && documentsResult.length > 0) {
                                            for (let j = 0; j < documentsResult.length; j++) {
                                                if (documentsResult[j].isRequired && !documentsResult[j].isVerified) {
                                                    isVerified = false;
                                                }
                                            }
                                        } else {
                                            isVerified = false;
                                        }
                                        result[0].isVerifiedProfile = isVerified;

                                        result[0].totalView = 0;
                                        result[0].todayView = 0;
                                        let totalViewSql = `SELECT COUNT(id) as totalView FROM userviewprofilehistories WHERE userId = ` + req.body.id;
                                        let totalViewResult = await header.query(totalViewSql);
                                        if (totalViewResult && totalViewResult.length > 0) {
                                            result[0].totalView = totalViewResult[0].totalView
                                        }
                                        let todayViewSql = `SELECT COUNT(id) as totalView FROM userviewprofilehistories WHERE userId = ` + req.body.id + ` AND DATE(transactionDate) = DATE(CURRENT_TIMESTAMP())`;
                                        let todayViewResult = await header.query(todayViewSql);
                                        if (todayViewResult && todayViewResult.length > 0) {
                                            result[0].todayView = todayViewResult[0].totalView
                                        }

                                        let userflagvalues = `SELECT ufv.*, uf.flagName, uf.displayName FROM userflagvalues ufv
                                            LEFT JOIN userflags uf ON uf.id = ufv.userFlagId
                                            WHERE ufv.userId = ` + req.body.id;
                                        result[0].userFlags = await header.query(userflagvalues);

                                        let getUserAuthSql = `SELECT * FROM userauthdata WHERE userId = ` + req.body.id;
                                        let getUserAuthResult = await header.query(getUserAuthSql)
                                        result[0].isOAuth = (getUserAuthResult && getUserAuthResult.length > 0) ? true : false;
                                        result[0].isAppleLogin = (getUserAuthResult && getUserAuthResult.length > 0 && getUserAuthResult[0].authProviderId == 3) ? true : false;

                                        result[0].userWalletAmount = 0;
                                        let getUserWalletSql = `SELECT * FROM userwallets WHERE userId = ` + result[0].id;
                                        let getUserWalletResult = await header.query(getUserWalletSql);
                                        if (getUserWalletResult && getUserWalletResult.length > 0) {
                                            result[0].userWalletAmount = getUserWalletResult[0].amount
                                        }

                                        if (req.body.isSignup) {

                                            let adminUserSql = `SELECT * FROM users where id IN(select userId from userroles where (roleId = 1 OR roleId = 3)) AND isActive  = true AND isDelete = false`;
                                            let adminUserResult = await header.query(adminUserSql);
                                            if (adminUserResult && adminUserResult.length > 0) {
                                                for (let a = 0; a < adminUserResult.length; a++) {
                                                    if (adminUserResult[a].isReceiveMail) {
                                                        let resultEmail = await sendEmail(config.emailMatrimonyNewUserRegister.fromName + ' <' + config.emailMatrimonyNewUserRegister.fromEmail + '>'
                                                            , [adminUserResult[a].email]
                                                            , config.emailMatrimonyNewUserRegister.subject
                                                            , ""
                                                            , config.emailMatrimonyNewUserRegister.html
                                                                .replace("[User's Full Name]", result[0].firstName + " " + result[0].lastName)
                                                                .replace("[User's Contact No]", result[0].contactNo)
                                                                .replace("[User's Email Address]", result[0].email)
                                                            , null, null);
                                                        console.log(resultEmail)
                                                    }
                                                    if (adminUserResult[a].isReceiveNotification) {
                                                        let deviceDetailSql = `SELECT * FROM userdevicedetail WHERE userId = ` + adminUserResult[a].id + ` AND fcmToken IS NOT NULL`;
                                                        let deviceDetailResult = await header.query(deviceDetailSql);
                                                        if (deviceDetailResult && deviceDetailResult.length > 0) {
                                                            let title = "New User Register";
                                                            let description = "New User " + result[0].firstName + " " + result[0].lastName + " registered in system. Please verify document";
                                                            let notificationSql = `INSERT INTO usernotifications(userId, title, message, bodyJson, imageUrl, createdBy, modifiedBy)
                                                    VALUES(` + adminUserResult[a].id + `,'` + title + `', '` + description + `', null, null, ` + authorizationResult.currentUser.id + `, ` + authorizationResult.currentUser.id + `)`
                                                            let notificationResult = await header.query(notificationSql);

                                                            await notificationContainer.sendMultipleNotification([deviceDetailResult[0].fcmToken], null, title, description, '', null, null, 0);
                                                            console.log("Send" + deviceDetailResult[0].fcmToken);
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        await header.commit();
                                        let successResult = new ResultSuccess(200, true, 'Update User Personal Detail', result, 1, authorizationResult.token);
                                        return res.status(200).send(successResult);
                                    } else {
                                        await header.rollback();
                                        let errorResult = new ResultError(400, true, "users.updateUserProfileDetail() Error", new Error('Error While Updating Data'), '');
                                        next(errorResult);
                                    }
                                } else {
                                    await header.rollback();
                                    let errorResult = new ResultError(400, true, "users.updateUserProfileDetail() Error", new Error('Error While Updating Data'), '');
                                    next(errorResult);
                                }
                            } else {
                                await header.rollback();
                                let errorResult = new ResultError(400, true, "users.updateUserProfileDetail() Error", new Error('Error While Updating Data'), '');
                                next(errorResult);
                            }
                        } else {
                            let insertAddress = `INSERT INTO addresses(addressLine1, addressLine2, pincode, cityId, districtId, stateId, countryId, countryName, stateName, cityName, latitude, longitude
                            , createdBy, modifiedBy) VALUES('` + req.body.addressLine1 + `','` + req.body.addressLine2 + `','` + req.body.pincode + `', ` + (req.body.cityId ? req.body.cityId : null) + `
                            , ` + (req.body.districtId ? req.body.districtId : null) + `, ` + (req.body.stateId ? req.body.stateId : null) + `, ` + (req.body.countryId ? req.body.countryId : null) + `
                            , '` + req.body.countryName + `','` + req.body.stateName + `','` + req.body.cityName + `', ` + req.body.latitude + `, ` + req.body.longitude + `,` + userId + `,` + userId + `)`;
                            let addressResult = await header.query(insertAddress);
                            if (addressResult && addressResult.insertId > 0) {
                                req.body.addressId = addressResult.insertId;
                                let insertSql = `INSERT INTO userpersonaldetail(userId, addressId, religionId, communityId, maritalStatusId, occupationId, educationId, subCommunityId, dietId, annualIncomeId, heightId, birthDate
                                , languages, eyeColor, businessName, companyName, employmentTypeId, expectation, aboutMe, createdBy, modifiedBy) VALUES(` + req.body.id + `,` + req.body.addressId + `,` + req.body.religionId + `
                                ,` + req.body.communityId + `,` + req.body.maritalStatusId + `,` + req.body.occupationId + `,` + req.body.educationId + `,` + req.body.subCommunityId + `,` + req.body.dietId + `
                                ,` + req.body.annualIncomeId + `,` + req.body.heightId + `,'` + bDate + `','` + req.body.languages + `','` + req.body.eyeColor + `', '` + req.body.businessName + `', '` + req.body.companyName + `'
                                , ` + req.body.employmentTypeId + `, '` + req.body.expectation + `', '` + req.body.aboutMe + `',` + userId + `,` + userId + `)`;
                                result = await header.query(insertSql);
                                if (result && result.affectedRows > 0) {
                                    let sql = `SELECT u.id, u.firstName, u.middleName, u.lastName, u.gender, u.email, u.contactNo
                                    , upd.birthDate, upd.languages, upd.eyeColor, upd.expectation, upd.aboutMe, upd.weight, upd.profileForId, pf.name as profileForName
                                    , img.imageUrl, r.name as religion, ms.name as maritalStatus, c.name as community, o.name as occupation, e.name as education, sc.name as subCommunity
                                , ai.value as annualIncome, d.name as diet, h.name as height
                                , addr.addressLine1, addr.addressLine2, addr.pincode, addr.cityId, addr.districtId, addr.stateId, addr.countryId
                                , cit.name as cityName, ds.name as districtName, st.name as stateName, cou.name as countryName
                                , em.name as employmentType, DATE_FORMAT(FROM_DAYS(DATEDIFF(now(),upd.birthDate)), '%Y')+0 AS age
                                FROM users u
                                LEFT JOIN userroles ur ON ur.userId = u.id
                                LEFT JOIN images img ON img.id = u.imageId
                                LEFT JOIN userpersonaldetail upd ON upd.userId = u.id
                                LEFT JOIN religion r ON r.id = upd.religionId
                                LEFT JOIN maritalstatus ms ON ms.id = upd.maritalStatusId
                                LEFT JOIN community c ON c.id = upd.communityId
                                LEFT JOIN occupation o ON o.id = upd.occupationId
                                LEFT JOIN education e ON e.id = upd.educationId
                                LEFT JOIN subcommunity sc ON sc.id = upd.subCommunityId
                                LEFT JOIN annualincome ai ON ai.id = upd.annualIncomeId
                                LEFT JOIN diet d ON d.id = upd.dietId
                                LEFT JOIN height h ON h.id = upd.heightId
                                LEFT JOIN addresses addr ON addr.id = upd.addressId
                                LEFT JOIN cities cit ON addr.cityId = cit.id
                                LEFT JOIN districts ds ON addr.districtId = ds.id
                                LEFT JOIN state st ON addr.stateId = st.id
                                LEFT JOIN countries cou ON addr.countryId = cou.id
                                LEFT JOIN employmenttype em ON em.id = upd.employmenttypeId
                                LEFT JOIN profilefor pf ON pf.id = upd.profileForId
                                 WHERE ur.roleId = 2 AND u.id = ` + req.body.id;
                                    let result = await header.query(sql);

                                    // let systemFlags = `SELECT * FROM systemflags where flagGroupId = 2`;
                                    // let _systemFlags = await header.query(systemFlags);
                                    // let _host;
                                    // let _port;
                                    // let _secure;
                                    // let _user;
                                    // let _password;

                                    // for (let i = 0; i < _systemFlags.length; i++) {
                                    //     if (_systemFlags[i].id == 4) {
                                    //         _host = _systemFlags[i].value;
                                    //     } else if (_systemFlags[i].id == 5) {
                                    //         _port = parseInt(_systemFlags[i].value);
                                    //     } else if (_systemFlags[i].id == 6) {
                                    //         if (_systemFlags[i].value == '1') {
                                    //             _secure = true;
                                    //         } else {
                                    //             _secure = false;
                                    //         }
                                    //     } else if (_systemFlags[i].id == 1) {
                                    //         _user = _systemFlags[i].value;
                                    //     } else if (_systemFlags[i].id == 2) {
                                    //         _password = _systemFlags[i].value;
                                    //     }
                                    // }
                                    let adminUserSql = `SELECT u.* FROM users u INNER JOIN userroles ur ON ur.userId = u.id WHERE (ur.roleId = 1 OR ur.roleId = 3) AND u.isActive && u.isReceiveMail && !u.isDelete`
                                    let adminUserResult = await header.query(adminUserSql);
                                    let emails = [];
                                    if (adminUserResult && adminUserResult.length > 0) {
                                        for (let i = 0; i < adminUserResult.length; i++) {
                                            if (adminUserResult[i].email)
                                                emails.push(adminUserResult[i].email)
                                        }

                                    }
                                    let resultEmail = await sendEmail(config.emailMatrimonyNewUserRegister.fromName + ' <' + config.emailMatrimonyNewUserRegister.fromEmail + '>'
                                        , emails
                                        , config.emailMatrimonyNewUserRegister.subject
                                        , ""
                                        , config.emailMatrimonyNewUserRegister.html
                                            .replace("[User's Full Name]", result[0].firstName + " " + result[0].lastName)
                                            .replace("[User's Contact No]", result[0].contactNo)
                                            .replace("[User's Email Address]", result[0].email)
                                        , null, null);

                                    await header.commit();
                                    let successResult = new ResultSuccess(200, true, 'Insert User Personal Detail', result, 1, authorizationResult.token);
                                    return res.status(200).send(successResult);
                                } else {
                                    await header.rollback();
                                    let errorResult = new ResultError(400, true, "users.updateUserProfileDetail() Error", new Error('Error While Inserting Data'), '');
                                    next(errorResult);
                                }
                            } else {
                                await header.rollback();
                                let errorResult = new ResultError(400, true, "users.updateUserProfileDetail() Error", new Error('Error While Inserting Data'), '');
                                next(errorResult);
                            }
                        }
                    } else {
                        await header.rollback();
                        let errorResult = new ResultError(400, true, "users.updateUserProfileDetail() Error", new Error('Error While Updating Data'), '');
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
        let errorResult = new ResultError(500, true, 'users.updateUserProfileDetail() Exception', error, '');
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
                    let resultEmail = await sendEmail(config.emailMatrimonySetPassword.fromName + ' <' + config.emailMatrimonySetPassword.fromEmail + '>', [userData[0].email], config.emailMatrimonySetPassword.subject, "", config.emailMatrimonySetPassword.html.replace("[VERIFICATION_TOKEN]", token).replace("[NAME]", (userData[0].firstName + ' ' + userData[0].lastName)), null, null);
                    await header.commit();
                    console.log(userData[0].firstName)
                    console.log(userData[0].lastName)
                    result = resultEmail;
                    let successResult = new ResultSuccess(200, true, 'Email sent successfully!', result, 1, "");
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

const sendEmail = async (from: string, to: string[], subject: string, text: string, html: any, fileName: any, invoicePdf: any, ccMails?: string[]) => {
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
            cc: ccMails,
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
                            return res.status(401).json({
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

const changeContact = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Change Contact');
        let requiredFields = ['oldContact', 'newContact'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let currentUser = authorizationResult.currentUser;
                let userId = currentUser.id;
                let result;
                let searchSql = `SELECT * FROM users WHERE contactNo = '` + req.body.oldContact + `' AND id = ` + userId;
                let searchResult = await header.query(searchSql);
                if (searchResult && searchResult.length > 0) {
                    let checkSql = `SELECT * FROM users WHERE contactNo = '` + req.body.newContact + `' AND id != ` + userId + ``;
                    result = await header.query(checkSql);
                    if (result && result.length > 0) {
                        let errorResult = new ResultError(203, true, 'Contact no. Already Exist', new Error('ContactNo Already Exist'), '');
                        next(errorResult);
                    } else {
                        let sql = `UPDATE users SET contactNo = '` + req.body.newContact + `' where id = ` + userId + ``;
                        result = await header.query(sql);
                        if (result && result.affectedRows > 0) {
                            let successResult = new ResultSuccess(200, true, 'Contact Change successfully!', result, 1, "null");
                            return res.status(200).send(successResult);
                        } else {
                            await header.rollback();
                            let errorResult = new ResultError(400, true, "users.changeContact() Error", new Error('Error While Change Contact'), '');
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
        let errorResult = new ResultError(500, true, 'users.changeContact() Exception', error, '');
        next(errorResult);
    }
};

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
                        let errorResult = new ResultError(203, true, "Email Already exists", new Error('users.changeEmail() Error'), '');
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

const searchUser = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Application User');
        let userId = 0;
        let authorizationResult;
        if (req.headers['authorization']) {
            authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let currentUser = authorizationResult.currentUser;
                userId = currentUser ? currentUser.id : 0;
            }
            else {
                let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
                next(errorResult);
            }
        }
        let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
        let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
        let sql = `SELECT u.id, udd.fcmtoken, img.imageUrl, u.firstName, u.middleName, u.lastName, u.contactNo, u.email, u.gender
            , upa.birthDate, DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0 AS age, upa.eyeColor, upa.languages, upa.expectation, upa.aboutMe, upa.weight, upa.profileForId, pf.name as profileForName
            , addr.addressLine1, addr.addressLine2, addr.pincode, addr.cityId, addr.districtId, addr.stateId, addr.countryId
            , cit.name as cityName, ds.name as districtName, st.name as stateName, cou.name as countryName
            , ms.name as maritalStatus, r.name as religion, c.name as community, o.name as occupation, e.name as education, sc.name as subCommunity, ai.value as annualIncome
            , d.name as diet, h.name as height, em.name as employmentType
            , u.id IN (select proposalUserId from userproposals where userId = ` + userId + `) as isProposed
            , u.id IN (select favUserId from userfavourites where userId = ` + userId + `) as isFavourite
            , addr.latitude, addr.longitude
            FROM users u
            LEFT JOIN userdevicedetail udd ON udd.userId = u.id
            LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
            LEFT JOIN userroles ur ON ur.userId = u.id
            LEFT JOIN images img ON img.id = u.imageId
            LEFT JOIN maritalstatus ms ON ms.id = upa.maritalStatusId
            LEFT JOIN religion r ON r.id = upa.religionId
            LEFT JOIN community c ON c.id = upa.communityId
            LEFT JOIN occupation o ON o.id = upa.occupationId
            LEFT JOIN education e ON e.id = upa.educationId
            LEFT JOIN subcommunity sc ON sc.id = upa.subCommunityId
            LEFT JOIN annualincome ai ON ai.id = upa.annualIncomeId
            LEFT JOIN addresses addr ON addr.id = upa.addressId
            LEFT JOIN cities cit ON addr.cityId = cit.id
            LEFT JOIN districts ds ON addr.districtId = ds.id
            LEFT JOIN state st ON addr.stateId = st.id
            LEFT JOIN countries cou ON addr.countryId = cou.id
            LEFT JOIN diet d ON d.id = upa.dietId
            LEFT JOIN height h ON h.id = upa.heightId            
            LEFT JOIN employmenttype em ON em.id = upa.employmenttypeId
            LEFT JOIN profilefor pf ON pf.id = upa.profileForId
            WHERE ur.roleId = 2 AND u.id != ` + userId + ` AND (upa.userId = u.id) AND u.id  AND
            (
                u.id NOT IN (select userBlockId from userblock where userId = ` + userId + `)  
                and u.id NOT IN (select userId from userblock where userBlockId = ` + userId + `)
                and u.id NOT IN (select blockRequestUserId from userblockrequest where status = true AND userId = ` + userId + `)
            )`;

        if (req.body.searchString) {
            sql += ` AND (u.firstName LIKE '%` + req.body.searchString + `%' OR u.lastName LIKE '%` + req.body.searchString + `%' OR u.middleName LIKE '%` + req.body.searchString + `%' 
                OR u.contactNo LIKE '%` + req.body.searchString + `%' OR u.email LIKE '%` + req.body.searchString + `%' OR u.gender LIKE '%` + req.body.searchString + `%'
                OR pf.name LIKE '%` + req.body.searchString + `%')`;
        }
        if (req.body.gender) {
            sql += ` AND u.gender = '` + req.body.gender + `'`;
        }
        if (req.body.occupationId && req.body.occupationId.length) {
            sql += ` AND o.id in (` + req.body.occupationId.toString() + `)`;
        }
        if (req.body.educationId && req.body.educationId.length) {
            sql += ` AND e.id in( ` + req.body.educationId.toString() + `)`;
        }
        if (req.body.maritalStatusId && req.body.maritalStatusId.length) {
            sql += ` AND ms.id in(` + req.body.maritalStatusId.toString() + `)`;
        }
        if (req.body.height1 && req.body.height2) {
            sql += ` AND h.name BETWEEN ` + req.body.height1 + ` AND ` + req.body.height2 + ``;
        }
        if (req.body.cityName) {
            sql += ` AND (addr.cityName LIKE '%` + req.body.cityName + `%')`
        }
        if (req.body.stateId) {
            sql += ` AND st.id = ` + req.body.stateId;
        }
        if (req.body.countryIds) {
            sql += ` AND cou.id IN` + req.body.countryIds.tostring();
        }
        if (req.body.stateIds) {
            sql += ` AND st.id IN` + req.body.stateIds.tostring();
        }
        if (req.body.districtIds) {
            sql += ` AND ds.id IN` + req.body.districtIds.tostring();
        }
        if (req.body.cityIds) {
            sql += ` AND cit.id IN` + req.body.cityIds.tostring();
        }
        if (req.body.age1 && req.body.age2) {
            sql += ` AND DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0 BETWEEN ` + req.body.age1 + ` AND ` + req.body.age2 + ``;
        }
        //sql +=` order by u.createdDate desc`
        if (startIndex != null && fetchRecord != null) {
            sql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
        }
        let result = await header.query(sql);
        if (result) {
            for (let i = 0; i < result.length; i++) {
                result[i].isVerifiedProfile = false;
                let isVerified = true
                let docVerifiedSql = `SELECT * FROM userdocument WHERE userId =` + result[i].id;
                let docVerifiedResult = await header.query(docVerifiedSql);
                if (docVerifiedResult && docVerifiedResult.length > 0) {
                    for (let j = 0; j < docVerifiedResult.length; j++) {
                        if (docVerifiedResult[j].isRequired && !docVerifiedResult[j].isVerified) {
                            isVerified = false;
                        }
                    }
                } else {
                    isVerified = false;
                }
                result[i].isVerifiedProfile = isVerified;
            }
            let successResult = new ResultSuccess(200, true, 'Get Search User Successfully', result, result.length, authorizationResult ? authorizationResult.token : '');
            return res.status(200).send(successResult);
        } else {
            let errorResult = new ResultError(400, true, 'Data Not Available', new Error('Data Not Available'), '');
            next(errorResult);
        }
        // } else {
        //     let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
        //     next(errorResult);
        // }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'users.searchUser() Exception', error, '');
        next(errorResult);
    }
};

const updateUserFlagValues = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Update User Flag Values');
        let requiredFields = ['id', 'userFlagId', 'userFlagValue'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let currentUser = authorizationResult.currentUser;
                let userId = currentUser.id;
                let sql = `UPDATE userflagvalues SET userFlagId = ` + req.body.userFlagId + `, userFlagValue = ` + req.body.userFlagValue + ` WHERE id = ` + req.body.id;
                let result = await header.query(sql);
                if (result && result.affectedRows > 0) {
                    let successResult = new ResultSuccess(200, true, 'Update User Flag Value successfully!', result, 1, "null");
                    return res.status(200).send(successResult);
                } else {
                    await header.rollback();
                    let errorResult = new ResultError(400, true, "users.updateUserFlagValues() Error", new Error('Error While Upadating Data'), '');
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
        let errorResult = new ResultError(500, true, 'users.updateUserFlagValues() Exception', error, '');
        next(errorResult);
    }
}

const getNearestApplicant = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Get Nearest Applicant');
        let requiredFields = [''];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let userId = 0;
            let authorizationResult;
            if (req.headers['authorization']) {
                authorizationResult = await header.validateAuthorization(req, res, next);
                if (authorizationResult.statusCode == 200) {
                    let currentUser = authorizationResult.currentUser;
                    userId = currentUser ? currentUser.id : 0;
                }
                else {
                    let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
                    next(errorResult);
                }
            }
            let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
            let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
            // SELECT u.id, upa.userId, img.imageUrl, u.firstName, u.middleName, u.lastName, u.contactNo, u.email, u.gender, upa.birthDate, DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0 AS age, upa.eyeColor, upa.languages, addr.addressLine1, addr.addressLine2, addr.pincode, addr.cityName, addr.stateName AS state,addr.stateName AS country, ms.name as maritalStatus, r.name as religion, c.name as community, o.name as occupation, e.name as education, sc.name as subCommunity, ai.value as annualIncome, d.name as diet, h.name as height , u.id IN (select proposalUserId from userproposals where userId = ` + userId + `) as isProposed,
            // u.id IN (select favUserId from userfavourites where userId = ` + userId + `) as isFavourite
            let sql = `SELECT u.id, addr.latitude, addr.longitude
                FROM users u
                LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                LEFT JOIN userroles ur ON ur.userId = u.id
                LEFT JOIN images img ON img.id = u.imageId
                LEFT JOIN maritalstatus ms ON ms.id = upa.maritalStatusId
                LEFT JOIN addresses addr ON addr.id = upa.addressId
                LEFT JOIN religion r ON r.id = upa.religionId
                LEFT JOIN community c ON c.id = upa.communityId
                LEFT JOIN occupation o ON o.id = upa.occupationId
                LEFT JOIN education e ON e.id = upa.educationId
                LEFT JOIN subcommunity sc ON sc.id = upa.subCommunityId
                LEFT JOIN annualincome ai ON ai.id = upa.annualIncomeId
                LEFT JOIN diet d ON d.id = upa.dietId
                LEFT JOIN height h ON h.id = upa.heightId
                WHERE ur.roleId = 2 AND u.id != ` + userId + ` AND (upa.userId = u.id) AND u.id  AND
                (
                    u.id NOT IN (select userBlockId from userblock where userId = ` + userId + `)  
                    and u.id NOT IN (select userId from userblock where userBlockId = ` + userId + `)
                    and u.id NOT IN (select blockRequestUserId from userblockrequest where status = true AND userId = ` + userId + `)
                )`;
            let result = await header.query(sql);
            if (result && result.length >= 0) {
                let userSql = `SELECT addr.* FROM userpersonaldetail upd INNER JOIN addresses addr ON addr.id = upd.addressId WHERE upd.userId = ` + userId;
                let userResult = await header.query(userSql);

                let distanceArray = [];
                let latestUserIds = [];
                for (let i = 0; i < result.length; i++) {
                    let km = await distance((userResult && userResult.length > 0 && userResult[0].latitude) ? userResult[0].latitude : 21.144539, (userResult && userResult.length > 0 && userResult[0].longitude) ? userResult[0].longitude : 73.094200
                        , result[i].latitude ? result[i].latitude : 21.144539, result[i].longitude ? result[i].longitude : 73.094200, "K");
                    let distanceObj = {
                        "userId": result[i].id,
                        "distance": parseFloat(km + "")
                    }
                    distanceArray.push(JSON.parse(JSON.stringify(distanceObj)));
                }
                distanceArray.sort((a, b) => {
                    if (a.distance > b.distance) {
                        return 1
                    } else {
                        return -1
                    }
                });
                if (distanceArray && distanceArray.length > 0) {
                    if (startIndex != null && fetchRecord != null) {
                        distanceArray = distanceArray.slice(startIndex, (startIndex + fetchRecord))
                    }
                    latestUserIds = distanceArray.map(x => x.userId);
                }
                if (distanceArray && distanceArray.length > 0) {
                    // let getSql = `SELECT u.id, upa.userId, img.imageUrl, u.firstName, u.middleName, u.lastName, u.contactNo, u.email, u.gender, upa.birthDate, DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0 AS age, upa.eyeColor, upa.languages
                    // , addr.addressLine1, addr.addressLine2, addr.pincode, addr.cityId, addr.districtId, addr.stateId, addr.countryId
                    // , cit.name as cityName, ds.name as districtName, st.name as stateName, cou.name as countryName
                    // , ms.name as maritalStatus, r.name as religion, c.name as community, o.name as occupation, e.name as education, sc.name as subCommunity, ai.value as annualIncome, d.name as diet, h.name as height , u.id IN (select proposalUserId from userproposals where userId = ` + userId + `) as isProposed,
                    // u.id IN (select favUserId from userfavourites where userId = ` + userId + `) as isFavourite, addr.latitude, addr.longitude
                    // FROM users u
                    // LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                    // LEFT JOIN userroles ur ON ur.userId = u.id
                    // LEFT JOIN images img ON img.id = u.imageId
                    // LEFT JOIN maritalstatus ms ON ms.id = upa.maritalStatusId
                    // LEFT JOIN addresses addr ON addr.id = upa.addressId
                    // LEFT JOIN cities cit ON addr.cityId = cit.id
                    // LEFT JOIN districts ds ON addr.districtId = ds.id
                    // LEFT JOIN state st ON addr.stateId = st.id
                    // LEFT JOIN countries cou ON addr.countryId = cou.id
                    // LEFT JOIN religion r ON r.id = upa.religionId
                    // LEFT JOIN community c ON c.id = upa.communityId
                    // LEFT JOIN occupation o ON o.id = upa.occupationId
                    // LEFT JOIN education e ON e.id = upa.educationId
                    // LEFT JOIN subcommunity sc ON sc.id = upa.subCommunityId
                    // LEFT JOIN annualincome ai ON ai.id = upa.annualIncomeId
                    // LEFT JOIN diet d ON d.id = upa.dietId
                    // LEFT JOIN height h ON h.id = upa.heightId
                    // WHERE ur.roleId = 2 AND u.id != ` + userId + ` AND u.id IN(` + latestUserIds.toString() + `) AND (upa.userId = u.id) AND u.id  AND
                    // (
                    //     u.id NOT IN (select userBlockId from userblock where userId = ` + userId + `)  
                    //     and u.id NOT IN (select userId from userblock where userBlockId = ` + userId + `)
                    //     and u.id NOT IN (select blockRequestUserId from userblockrequest where status = true AND userId = ` + userId + `)
                    // )`;
                    let getSql = `SELECT u.id, udd.fcmtoken, img.imageUrl, u.firstName, u.middleName, u.lastName, u.contactNo, u.email, u.gender
                        , upa.birthDate, DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0 AS age, upa.eyeColor, upa.languages, upa.expectation, upa.aboutMe, upa.weight, upa.profileForId
                        , pf.name as profileForName
                        , addr.addressLine1, addr.addressLine2, addr.pincode, addr.cityId, addr.districtId, addr.stateId, addr.countryId
                        , cit.name as cityName, ds.name as districtName, st.name as stateName, cou.name as countryName
                        , ms.name as maritalStatus, r.name as religion, c.name as community, o.name as occupation, e.name as education, sc.name as subCommunity, ai.value as annualIncome
                        , d.name as diet, h.name as height, em.name as employmentType
                        , u.id IN (select proposalUserId from userproposals where userId = ` + userId + `) as isProposed
                        , u.id IN (select favUserId from userfavourites where userId = ` + userId + `) as isFavourite
                        , addr.latitude, addr.longitude
                        FROM users u
                        LEFT JOIN userdevicedetail udd ON udd.userId = u.id
                        LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                        LEFT JOIN userroles ur ON ur.userId = u.id
                        LEFT JOIN images img ON img.id = u.imageId
                        LEFT JOIN maritalstatus ms ON ms.id = upa.maritalStatusId
                        LEFT JOIN religion r ON r.id = upa.religionId
                        LEFT JOIN community c ON c.id = upa.communityId
                        LEFT JOIN occupation o ON o.id = upa.occupationId
                        LEFT JOIN education e ON e.id = upa.educationId
                        LEFT JOIN subcommunity sc ON sc.id = upa.subCommunityId
                        LEFT JOIN annualincome ai ON ai.id = upa.annualIncomeId
                        LEFT JOIN addresses addr ON addr.id = upa.addressId
                        LEFT JOIN cities cit ON addr.cityId = cit.id
                        LEFT JOIN districts ds ON addr.districtId = ds.id
                        LEFT JOIN state st ON addr.stateId = st.id
                        LEFT JOIN countries cou ON addr.countryId = cou.id
                        LEFT JOIN diet d ON d.id = upa.dietId
                        LEFT JOIN height h ON h.id = upa.heightId            
                        LEFT JOIN employmenttype em ON em.id = upa.employmenttypeId  
                        LEFT JOIN profilefor pf ON pf.id = upa.profileForId
                        WHERE ur.roleId = 2 AND u.id != ` + userId + ` AND u.id IN(` + latestUserIds.toString() + `) AND (upa.userId = u.id) AND u.id  AND
                        (
                            u.id NOT IN (select userBlockId from userblock where userId = ` + userId + `)  
                            and u.id NOT IN (select userId from userblock where userBlockId = ` + userId + `)
                            and u.id NOT IN (select blockRequestUserId from userblockrequest where status = true AND userId = ` + userId + `)
                        )`;
                    let getResult = await header.query(getSql);
                    if (getResult) {
                        for (let i = 0; i < getResult.length; i++) {
                            getResult[i].isVerifiedProfile = false;
                            let isVerified = true
                            let docVerifiedSql = `SELECT * FROM userdocument WHERE userId =` + getResult[i].id;
                            let docVerifiedResult = await header.query(docVerifiedSql);
                            if (docVerifiedResult && docVerifiedResult.length > 0) {
                                for (let j = 0; j < docVerifiedResult.length; j++) {
                                    if (docVerifiedResult[j].isRequired && !docVerifiedResult[j].isVerified) {
                                        isVerified = false;
                                    }
                                }
                            } else {
                                isVerified = false;
                            }
                            getResult[i].isVerifiedProfile = isVerified;
                        }
                        let successResult = new ResultSuccess(200, true, 'Get Nearest Users Successfully', getResult, getResult.length, authorizationResult ? authorizationResult.token : '');
                        return res.status(200).send(successResult);
                    } else {
                        let errorResult = new ResultError(400, true, 'Data Not Available', new Error('Data Not Available'), '');
                        next(errorResult);
                    }
                } else {
                    let successResult = new ResultSuccess(200, true, 'Get Nearest Users Successfully', [], 0, authorizationResult ? authorizationResult.token : '');
                    return res.status(200).send(successResult);
                }
            } else {
                let successResult = new ResultSuccess(200, true, 'Get Nearest Users Successfully', [], 0, authorizationResult ? authorizationResult.token : '');
                return res.status(200).send(successResult);
            }
            // } else {
            //     let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
            //     next(errorResult);
            // }
        } else {
            await header.rollback();
            let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'users.getNearestApplicant() Exception', error, '');
        next(errorResult);
    }
}

var distance = async (lat1: number, lon1: number, lat2: number, lon2: number, unit: string) => {
    if ((lat1 == lat2) && (lon1 == lon2)) {
        return 0;
    }
    else {
        var radlat1 = Math.PI * lat1 / 180;
        var radlat2 = Math.PI * lat2 / 180;
        var theta = lon1 - lon2;
        var radtheta = Math.PI * theta / 180;
        var dist = Math.sin(radlat1) * Math.sin(radlat2) + Math.cos(radlat1) * Math.cos(radlat2) * Math.cos(radtheta);
        if (dist > 1) {
            dist = 1;
        }
        dist = Math.acos(dist);
        dist = dist * 180 / Math.PI;
        dist = dist * 60 * 1.1515;
        if (unit == "K") { dist = dist * 1.609344 }
        if (unit == "N") { dist = dist * 0.8684 }
        return dist;
    }
}

const getMostViewedApplicant = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Get Nearest Applicant');
        let requiredFields = [''];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult;
            let userId = 0;
            if (req.headers['authorization']) {
                authorizationResult = await header.validateAuthorization(req, res, next);
                if (authorizationResult.statusCode == 200) {
                    let currentUser = authorizationResult.currentUser;
                    userId = currentUser ? currentUser.id : 0;
                }
                else {
                    let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
                    next(errorResult);
                }
            }
            let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
            let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
            // let sql = `SELECT u.id, upa.userId, img.imageUrl, u.firstName, u.middleName, u.lastName, u.contactNo, u.email, u.gender, upa.birthDate, DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0 AS age, upa.eyeColor, upa.languages
            // , addr.addressLine1, addr.addressLine2, addr.pincode, addr.cityId, addr.districtId, addr.stateId, addr.countryId
            // , cit.name as cityName, ds.name as districtName, st.name as stateName, cou.name as countryName
            // , ms.name as maritalStatus, r.name as religion, c.name as community, o.name as occupation, e.name as education, sc.name as subCommunity, ai.value as annualIncome
            // , d.name as diet, h.name as height , u.id IN (select proposalUserId from userproposals where userId = ` + userId + `) as isProposed,
            // u.id IN (select favUserId from userfavourites where userId = ` + userId + `) as isFavourite, addr.latitude, addr.longitude
            // , (select count(id) from userviewprofilehistories where  userId = u.id ) as totalView
            // FROM users u
            // LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
            // LEFT JOIN userroles ur ON ur.userId = u.id
            // LEFT JOIN images img ON img.id = u.imageId
            // LEFT JOIN maritalstatus ms ON ms.id = upa.maritalStatusId
            // LEFT JOIN addresses addr ON addr.id = upa.addressId
            // LEFT JOIN cities cit ON addr.cityId = cit.id
            // LEFT JOIN districts ds ON addr.districtId = ds.id
            // LEFT JOIN state st ON addr.stateId = st.id
            // LEFT JOIN countries cou ON addr.countryId = cou.id
            // LEFT JOIN religion r ON r.id = upa.religionId
            // LEFT JOIN community c ON c.id = upa.communityId
            // LEFT JOIN occupation o ON o.id = upa.occupationId
            // LEFT JOIN education e ON e.id = upa.educationId
            // LEFT JOIN subcommunity sc ON sc.id = upa.subCommunityId
            // LEFT JOIN annualincome ai ON ai.id = upa.annualIncomeId
            // LEFT JOIN diet d ON d.id = upa.dietId
            // LEFT JOIN height h ON h.id = upa.heightId
            // WHERE ur.roleId = 2 AND u.id != ` + userId + ` AND (upa.userId = u.id) AND u.id  AND
            // (
            //     u.id NOT IN (select userBlockId from userblock where userId = ` + userId + `)  
            //     and u.id NOT IN (select userId from userblock where userBlockId = ` + userId + `)
            //     and u.id NOT IN (select blockRequestUserId from userblockrequest where status = true AND userId = ` + userId + `)
            // ) ORDER BY totalView DESC`;
            let sql = `SELECT u.id, udd.fcmtoken, img.imageUrl, u.firstName, u.middleName, u.lastName, u.contactNo, u.email, u.gender
                , upa.birthDate, DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0 AS age, upa.eyeColor, upa.languages, upa.expectation, upa.aboutMe, upa.weight, upa.profileForId, pf.name as profileForName
                , addr.addressLine1, addr.addressLine2, addr.pincode, addr.cityId, addr.districtId, addr.stateId, addr.countryId
                , cit.name as cityName, ds.name as districtName, st.name as stateName, cou.name as countryName
                , ms.name as maritalStatus, r.name as religion, c.name as community, o.name as occupation, e.name as education, sc.name as subCommunity, ai.value as annualIncome
                , d.name as diet, h.name as height, em.name as employmentType
                , u.id IN (select proposalUserId from userproposals where userId = ` + userId + `) as isProposed
                , u.id IN (select favUserId from userfavourites where userId = ` + userId + `) as isFavourite
                , addr.latitude, addr.longitude
                , (select count(id) from userviewprofilehistories where  userId = u.id ) as totalView
                FROM users u
                LEFT JOIN userdevicedetail udd ON udd.userId = u.id
                LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                LEFT JOIN userroles ur ON ur.userId = u.id
                LEFT JOIN images img ON img.id = u.imageId
                LEFT JOIN maritalstatus ms ON ms.id = upa.maritalStatusId
                LEFT JOIN religion r ON r.id = upa.religionId
                LEFT JOIN community c ON c.id = upa.communityId
                LEFT JOIN occupation o ON o.id = upa.occupationId
                LEFT JOIN education e ON e.id = upa.educationId
                LEFT JOIN subcommunity sc ON sc.id = upa.subCommunityId
                LEFT JOIN annualincome ai ON ai.id = upa.annualIncomeId
                LEFT JOIN addresses addr ON addr.id = upa.addressId
                LEFT JOIN cities cit ON addr.cityId = cit.id
                LEFT JOIN districts ds ON addr.districtId = ds.id
                LEFT JOIN state st ON addr.stateId = st.id
                LEFT JOIN countries cou ON addr.countryId = cou.id
                LEFT JOIN diet d ON d.id = upa.dietId
                LEFT JOIN height h ON h.id = upa.heightId            
                LEFT JOIN employmenttype em ON em.id = upa.employmenttypeId  
                LEFT JOIN profilefor pf ON pf.id = upa.profileForId
                WHERE ur.roleId = 2 AND u.id != ` + userId + ` AND (upa.userId = u.id) AND u.id  AND
                (
                    u.id NOT IN (select userBlockId from userblock where userId = ` + userId + `)  
                    and u.id NOT IN (select userId from userblock where userBlockId = ` + userId + `)
                    and u.id NOT IN (select blockRequestUserId from userblockrequest where status = true AND userId = ` + userId + `)
                ) ORDER BY totalView DESC`;
            if (startIndex != null && fetchRecord != null) {
                sql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
            }
            let result = await header.query(sql);
            if (result && result.length >= 0) {
                for (let i = 0; i < result.length; i++) {
                    result[i].isVerifiedProfile = false;
                    let isVerified = true
                    let docVerifiedSql = `SELECT * FROM userdocument WHERE userId =` + result[i].id;
                    let docVerifiedResult = await header.query(docVerifiedSql);
                    if (docVerifiedResult && docVerifiedResult.length > 0) {
                        for (let j = 0; j < docVerifiedResult.length; j++) {
                            if (docVerifiedResult[j].isRequired && !docVerifiedResult[j].isVerified) {
                                isVerified = false;
                            }
                        }
                    } else {
                        isVerified = false;
                    }
                    result[i].isVerifiedProfile = isVerified;
                }
                let successResult = new ResultSuccess(200, true, 'Get Most Viewed Users Successfully', result, result.length, authorizationResult ? authorizationResult.token : '');
                return res.status(200).send(successResult);
            } else {
                let successResult = new ResultSuccess(200, true, 'Get Most Viewed Users Successfully', [], 0, authorizationResult ? authorizationResult.token : '');
                return res.status(200).send(successResult);
            }
            // } else {
            //     let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
            //     next(errorResult);
            // }
        } else {
            await header.rollback();
            let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'users.getMostViewedApplicant() Exception', error, '');
        next(errorResult);
    }
}

const completeUserProfile = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Updating Users');
        let requiredFields = ['id', 'firstName', 'lastName', 'email', 'gender', 'birthDate', 'addressLine1', 'pincode', 'religionId', 'communityId', 'maritalStatusId', 'occupationId', 'educationId', 'annualIncomeId', 'heightId', 'languages', 'employmentTypeId'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                await header.beginTransaction();
                let currentUser = authorizationResult.currentUser;
                let userId = currentUser.id;
                req.body.contactNo = req.body.contactNo ? req.body.contactNo : '';
                req.body.middleName = req.body.middleName ? req.body.middleName : '';
                req.body.countryName = req.body.countryName ? req.body.countryName : '';
                req.body.stateName = req.body.stateName ? req.body.stateName : '';
                req.body.cityName = req.body.cityName ? req.body.cityName : '';
                req.body.aboutMe = req.body.aboutMe ? req.body.aboutMe : '';
                req.body.expectation = req.body.expectation ? req.body.expectation : '';
                req.body.eyeColor = req.body.eyeColor ? req.body.eyeColor : '';
                let birthDate = req.body.birthDate ? new Date(req.body.birthDate) : '';
                let bDate = new Date(birthDate).getFullYear().toString() + '-' + ("0" + (new Date(birthDate).getMonth() + 1)).slice(-2) + '-' + ("0" + new Date(birthDate).getDate()).slice(-2) + ' ' + ("0" + (new Date(birthDate).getHours())).slice(-2) + ':' + ("0" + (new Date(birthDate).getMinutes())).slice(-2) + ':' + ("0" + (new Date(birthDate).getSeconds())).slice(-2);

                let checkSql = `SELECT * FROM users WHERE email = '` + req.body.email + `' AND id != ` + req.body.id;
                let checkResult = await header.query(checkSql);
                if (checkResult && checkResult.length > 0) {
                    await header.rollback();
                    let message = 'Email Already Inserted';
                    return res.status(200).send(message);
                    // let errorResult = new ResultError(203, true, message, new Error(message), '');
                    // next(errorResult);

                } else {
                    let result;
                    let sql = `UPDATE users SET firstName = '` + req.body.firstName + `', middleName = '` + req.body.middleName + `', lastName = '` + req.body.lastName + `'
                , contactNo = '` + req.body.contactNo + `',email = '` + req.body.email + `',gender = '` + req.body.gender + `' WHERE id = ` + req.body.id + ``;
                    result = await header.query(sql);
                    if (result && result.affectedRows > 0) {
                        if (req.body.documents && req.body.documents.length > 0) {
                            for (let i = 0; i < req.body.documents.length; i++) {
                                if (req.body.documents[i].isRequired) {
                                    if (!req.body.documents[i].documentUrl) {
                                        let errorResult = new ResultError(400, true, "Document is Required", new Error('Document is Required'), '');
                                        next(errorResult);
                                        return errorResult;
                                    }
                                }
                                if (req.body.documents[i].documentUrl) {
                                    if (req.body.documents[i].id) {
                                        if (req.body.documents[i].documentUrl && req.body.documents[i].documentUrl.indexOf('content') == -1) {
                                            let userDocumentId = req.body.documents[i].id;
                                            let oldDocummentSql = `SELECT * FROM userdocument WHERE id = ` + userDocumentId;
                                            let oldDocummentResult = await header.query(oldDocummentSql);

                                            let image = req.body.documents[i].documentUrl;
                                            let data = image.split(',');
                                            if (data && data.length > 1) {
                                                image = image.split(',')[1]
                                            }

                                            let dir = './content';
                                            if (!fs.existsSync(dir)) {
                                                fs.mkdirSync(dir);
                                            }

                                            let dir1 = './content/userDocument';
                                            if (!fs.existsSync(dir1)) {
                                                fs.mkdirSync(dir1);
                                            }

                                            let dir2 = './content/userDocument/' + req.body.id;
                                            if (!fs.existsSync(dir2)) {
                                                fs.mkdirSync(dir2);
                                            }
                                            const fileContentsUser = new Buffer(image, 'base64')
                                            let imgPath = "./content/userDocument/" + req.body.id + "/" + userDocumentId + "-realImg.jpeg";

                                            fs.writeFileSync(imgPath, fileContentsUser, (err: any) => {
                                                if (err)
                                                    return console.error(err)
                                                console.log('file saved imagePath')
                                            });
                                            let imagePath = "./content/userDocument/" + req.body.id + "/" + userDocumentId + ".jpeg";
                                            await Jimp.read(imgPath)
                                                .then(async (lenna: any) => {
                                                    // return lenna
                                                    //     //.resize(100, 100) // resize
                                                    //     .quality(60) // set JPEG quality
                                                    //     // .greyscale() // set greyscale
                                                    //     // .write("lena-small-bw.jpg"); // save
                                                    //     .write(imagePath);
                                                    let data = lenna
                                                        //.resize(100, 100) // resize
                                                        // .quality(60) // set JPEG quality
                                                        // .greyscale() // set greyscale
                                                        // .write("lena-small-bw.jpg"); // save
                                                        .write(imagePath);


                                                    const image_act = await Jimp.read(imagePath);
                                                    const watermark = await Jimp.read('./content/systemflag/watermarkImage/watermarkImage.jpeg');
                                                    watermark.resize(image_act.getWidth() / 2, Jimp.AUTO);
                                                    const x = (image_act.getWidth() - watermark.getWidth()) / 2;
                                                    const y = (image_act.getHeight() - (watermark.getHeight() * 2));

                                                    image_act.composite(watermark, x, y, {
                                                        mode: Jimp.BLEND_SOURCE_OVER,
                                                        opacitySource: 0.5, // Adjust the opacity of the watermark
                                                    });
                                                    //imagePath = "./content/notification/" + notificationId + ".jpeg";
                                                    await image_act.writeAsync(imagePath);
                                                    return data;
                                                })
                                                .catch((err: any) => {
                                                    console.error(err);
                                                });
                                            let updateimagePathSql = `UPDATE userdocument SET documentUrl='` + imagePath.substring(2) + `' WHERE id=` + userDocumentId;
                                            let updateimagePathResult = await header.query(updateimagePathSql);
                                            if (updateimagePathResult && updateimagePathResult.affectedRows > 0) {
                                                // if (oldDocummentResult && oldDocummentResult.length > 0) {
                                                //     for (let d = 0; d < oldDocummentResult.length; d++) {
                                                //         if (oldDocummentResult[d].documentUrl) {
                                                //             let oldUrl = oldDocummentResult[d].documentUrl;
                                                //             let imagePath = "./" + oldUrl;
                                                //             if (fs.existsSync(imagePath)) {
                                                //                 fs.unlink(imagePath, (err: any) => {
                                                //                     if (err) throw err;
                                                //                     console.log(imagePath + ' was deleted');
                                                //                 });
                                                //             }

                                                //             let realImg = "./" + oldUrl.split(".")[0] + "-realImg." + oldUrl.split(".")[1];
                                                //             if (fs.existsSync(realImg)) {
                                                //                 fs.unlink(realImg, (err: any) => {
                                                //                     if (err) throw err;
                                                //                     console.log(realImg + ' was deleted');
                                                //                 });
                                                //             }
                                                //         }
                                                //     }
                                                // }
                                            } else {
                                                let errorResult = new ResultError(400, true, "users.updateUserProfilePic() Error", new Error('Error While Updating Profile Pic'), '');
                                                next(errorResult);
                                            }
                                        }
                                    } else {
                                        if (req.body.documents[i].documentUrl && req.body.documents[i].documentUrl.indexOf('content') == -1) {
                                            //let imageSql = `INSERT INTO images(createdBy, modifiedBy) VALUES (` + req.body.id + `,` + req.body.id + `)`;
                                            let userDocumentSql = `INSERT INTO userdocument(userId, documentTypeId, isVerified, isRequired, createdBy, modifiedBy) 
                                        VALUES(`+ req.body.id + `,` + req.body.documents[i].documentTypeId + `, 0, ` + req.body.documents[i].isRequired + `,` + req.body.id + `,` + req.body.id + `)`;
                                            result = await header.query(userDocumentSql);
                                            if (result.insertId) {
                                                let userDocumentId = result.insertId;

                                                let image = req.body.documents[i].documentUrl;
                                                let data = image.split(',');
                                                if (data && data.length > 1) {
                                                    image = image.split(',')[1]
                                                }

                                                let dir = './content';
                                                if (!fs.existsSync(dir)) {
                                                    fs.mkdirSync(dir);
                                                }

                                                let dir1 = './content/userDocument';
                                                if (!fs.existsSync(dir1)) {
                                                    fs.mkdirSync(dir1);
                                                }

                                                let dir2 = './content/userDocument/' + req.body.id;
                                                if (!fs.existsSync(dir2)) {
                                                    fs.mkdirSync(dir2);
                                                }
                                                const fileContentsUser = new Buffer(image, 'base64')
                                                let imgPath = "./content/userDocument/" + req.body.id + "/" + userDocumentId + "-realImg.jpeg";

                                                fs.writeFileSync(imgPath, fileContentsUser, (err: any) => {
                                                    if (err)
                                                        return console.error(err)
                                                    console.log('file saved imagePath')
                                                });
                                                let imagePath = "./content/userDocument/" + req.body.id + "/" + userDocumentId + ".jpeg";
                                                await Jimp.read(imgPath)
                                                    .then(async (lenna: any) => {
                                                        // return lenna
                                                        //     //.resize(100, 100) // resize
                                                        //     .quality(60) // set JPEG quality
                                                        //     // .greyscale() // set greyscale
                                                        //     // .write("lena-small-bw.jpg"); // save
                                                        //     .write(imagePath);
                                                        let data = lenna
                                                            //.resize(100, 100) // resize
                                                            // .quality(60) // set JPEG quality
                                                            // .greyscale() // set greyscale
                                                            // .write("lena-small-bw.jpg"); // save
                                                            .write(imagePath);


                                                        const image_act = await Jimp.read(imagePath);
                                                        const watermark = await Jimp.read('./content/systemflag/watermarkImage/watermarkImage.jpeg');
                                                        watermark.resize(image_act.getWidth() / 2, Jimp.AUTO);
                                                        const x = (image_act.getWidth() - watermark.getWidth()) / 2;
                                                        const y = (image_act.getHeight() - (watermark.getHeight() * 2));

                                                        image_act.composite(watermark, x, y, {
                                                            mode: Jimp.BLEND_SOURCE_OVER,
                                                            opacitySource: 0.5, // Adjust the opacity of the watermark
                                                        });
                                                        //imagePath = "./content/notification/" + notificationId + ".jpeg";
                                                        await image_act.writeAsync(imagePath);
                                                        return data;
                                                    })
                                                    .catch((err: any) => {
                                                        console.error(err);
                                                    });
                                                let updateimagePathSql = `UPDATE userdocument SET documentUrl='` + imagePath.substring(2) + `' WHERE id=` + userDocumentId;
                                                let updateimagePathResult = await header.query(updateimagePathSql);
                                                if (updateimagePathResult && updateimagePathResult.affectedRows > 0) {

                                                } else {
                                                    let errorResult = new ResultError(400, true, "users.updateUserProfilePic() Error", new Error('Error While Updating Profile Pic'), '');
                                                    next(errorResult);
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    if (req.body.documents[i].id) {
                                        let oldDocummentSql = `SELECT * FROM userdocument WHERE id = ` + req.body.documents[i].id;
                                        let oldDocummentResult = await header.query(oldDocummentSql);
                                        let updateimagePathSql = `DELETE FROM userdocument WHERE id=` + req.body.documents[i].id;
                                        let updateimagePathResult = await header.query(updateimagePathSql);
                                        if (updateimagePathResult && updateimagePathResult.affectedRows > 0) {
                                            if (oldDocummentResult && oldDocummentResult.length > 0) {
                                                for (let d = 0; d < oldDocummentResult.length; d++) {
                                                    if (oldDocummentResult[d].documentUrl) {
                                                        let oldUrl = oldDocummentResult[d].documentUrl;
                                                        let imagePath = "./" + oldUrl;
                                                        if (fs.existsSync(imagePath)) {
                                                            fs.unlink(imagePath, (err: any) => {
                                                                if (err) throw err;
                                                                console.log(imagePath + ' was deleted');
                                                            });
                                                        }

                                                        let realImg = "./" + oldUrl.split(".")[0] + "-realImg." + oldUrl.split(".")[1];
                                                        if (fs.existsSync(realImg)) {
                                                            fs.unlink(realImg, (err: any) => {
                                                                if (err) throw err;
                                                                console.log(realImg + ' was deleted');
                                                            });
                                                        }
                                                    }
                                                }
                                            }
                                        } else {
                                            let errorResult = new ResultError(400, true, "users.updateUserProfilePic() Error", new Error('Error While Updating Profile Pic'), '');
                                            next(errorResult);
                                        }
                                    }
                                }
                            }
                        }
                        let userPerDetailSql = `SELECT * FROM userpersonaldetail WHERE userId = ` + req.body.id + ``;
                        result = await header.query(userPerDetailSql);
                        if (result && result.length > 0) {
                            let userpersonaldetailId = result[0].id;
                            req.body.addressId = result[0].addressId;
                            req.body.birthDate = req.body.birthDate ? req.body.birthDate : '';
                            let updateAddSql = `UPDATE addresses SET addressLine1 = '` + req.body.addressLine1 + `', addressLine2 = '` + req.body.addressLine2 + `', pincode = '` + req.body.pincode + `'
                        , cityId = ` + (req.body.cityId ? req.body.cityId : null) + `, districtId = ` + (req.body.districtId ? req.body.districtId : null) + `
                        , stateId = ` + (req.body.stateId ? req.body.stateId : null) + `, countryId = ` + (req.body.countryId ? req.body.countryId : null) + `
                        , countryName = '` + req.body.countryName + `', stateName = '` + req.body.stateName + `', cityName = '` + req.body.cityName + `' 
                        , latitude = `+ (req.body.latitude ? req.body.latitude : null) + `, longitude = ` + (req.body.longitude ? req.body.longitude : null) + ` WHERE id = ` + req.body.addressId + ``;
                            let updateAddressResult = await header.query(updateAddSql);
                            if (updateAddressResult && updateAddressResult.affectedRows > 0) {
                                // let addressId = updateAddressResult[0].id;
                                let updateSql = `UPDATE userpersonaldetail SET addressId = ` + req.body.addressId + `, religionId = ` + req.body.religionId + `,communityId = ` + req.body.communityId + `,maritalStatusId = ` + req.body.maritalStatusId + `,occupationId = ` + req.body.occupationId + `,educationId = ` + req.body.educationId + `,subCommunityId = ` + req.body.subCommunityId + `,dietId = ` + req.body.dietId + `,annualIncomeId = ` + req.body.annualIncomeId + `,heightId = ` + req.body.heightId + `,birthDate = '` + bDate + `',languages = '` + req.body.languages + `',eyeColor = '` + req.body.eyeColor + `', businessName = '` + req.body.businessName + `', companyName = '` + req.body.companyName + `', employmentTypeId = ` + req.body.employmentTypeId + `, expectation = '` + req.body.expectation + `', aboutMe = '` + req.body.aboutMe + `'  WHERE id = ` + userpersonaldetailId + `,weight = ` + req.body.weight + `,profileForId = ` + req.body.profileForId + ``;
                                result = await header.query(updateSql);
                                if (result && result.affectedRows > 0) {
                                    let sql = `SELECT u.id, u.firstName, u.middleName, u.lastName, u.gender, u.email, u.contactNo
                                    , upd.birthDate, upd.languages, upd.eyeColor, upd.expectation, upd.aboutMe, upd.weight, upd.profileForId, pf.name as profileForName, img.imageUrl
                                , r.name as religion, ms.name as maritalStatus, c.name as community, o.name as occupation, e.name as education, sc.name as subCommunity, ai.value as annualIncome, d.name as diet, h.name as height
                                , addr.addressLine1, addr.addressLine2, addr.pincode, addr.cityId, addr.districtId, addr.stateId, addr.countryId
                                , cit.name as cityName, ds.name as districtName, st.name as stateName, cou.name as countryName
                                , em.name as employmentType, DATE_FORMAT(FROM_DAYS(DATEDIFF(now(),upd.birthDate)), '%Y')+0 AS age
                                , addr.latitude, addr.longitude
                                FROM users u
                                LEFT JOIN userroles ur ON ur.userId = u.id
                                LEFT JOIN images img ON img.id = u.imageId
                                LEFT JOIN userpersonaldetail upd ON upd.userId = u.id
                                LEFT JOIN religion r ON r.id = upd.religionId
                                LEFT JOIN maritalstatus ms ON ms.id = upd.maritalStatusId
                                LEFT JOIN community c ON c.id = upd.communityId
                                LEFT JOIN occupation o ON o.id = upd.occupationId
                                LEFT JOIN education e ON e.id = upd.educationId
                                LEFT JOIN subcommunity sc ON sc.id = upd.subCommunityId
                                LEFT JOIN annualincome ai ON ai.id = upd.annualIncomeId
                                LEFT JOIN diet d ON d.id = upd.dietId
                                LEFT JOIN height h ON h.id = upd.heightId
                                LEFT JOIN addresses addr ON addr.id = upd.addressId
                                LEFT JOIN cities cit ON addr.cityId = cit.id
                                LEFT JOIN districts ds ON addr.districtId = ds.id
                                LEFT JOIN state st ON addr.stateId = st.id
                                LEFT JOIN countries cou ON addr.countryId = cou.id
                                LEFT JOIN employmenttype em ON em.id = upd.employmenttypeId
                                LEFT JOIN profilefor pf ON pf.id = upd.profileForId
                                 WHERE ur.roleId = 2 AND u.id = ` + req.body.id;
                                    let result = await header.query(sql);

                                    if (result && result.length > 0) {
                                        result[0].isVerified = false;
                                        let isVerified = true;
                                        let documentsSql = `SELECT ud.*, dt.name as documentTypeName FROM userdocument ud INNER JOIN documenttype dt ON dt.id = ud.documentTypeId WHERE userId = ` + result[0].id;
                                        let documentsResult = await header.query(documentsSql);
                                        result[0].userDocuments = documentsResult;
                                        if (documentsResult && documentsResult.length > 0) {
                                            for (let j = 0; j < documentsResult.length; j++) {
                                                if (documentsResult[j].isRequired && !documentsResult[j].isVerified) {
                                                    isVerified = false;
                                                }
                                            }
                                        } else {
                                            isVerified = false;
                                        }
                                        result[0].isVerifiedProfile = isVerified;

                                        result[0].totalView = 0;
                                        result[0].todayView = 0;
                                        let totalViewSql = `SELECT COUNT(id) as totalView FROM userviewprofilehistories WHERE userId = ` + req.body.id;
                                        let totalViewResult = await header.query(totalViewSql);
                                        if (totalViewResult && totalViewResult.length > 0) {
                                            result[0].totalView = totalViewResult[0].totalView
                                        }
                                        let todayViewSql = `SELECT COUNT(id) as totalView FROM userviewprofilehistories WHERE userId = ` + req.body.id + ` AND DATE(transactionDate) = DATE(CURRENT_TIMESTAMP())`;
                                        let todayViewResult = await header.query(todayViewSql);
                                        if (todayViewResult && todayViewResult.length > 0) {
                                            result[0].todayView = todayViewResult[0].totalView
                                        }

                                        let userflagvalues = `SELECT ufv.*, uf.flagName, uf.displayName FROM userflagvalues ufv
                                            LEFT JOIN userflags uf ON uf.id = ufv.userFlagId
                                            WHERE ufv.userId = ` + req.body.id;
                                        result[0].userFlags = await header.query(userflagvalues);

                                        let getUserAuthSql = `SELECT * FROM userauthdata WHERE userId = ` + req.body.id;
                                        let getUserAuthResult = await header.query(getUserAuthSql)
                                        result[0].isOAuth = (getUserAuthResult && getUserAuthResult.length > 0) ? true : false;
                                        result[0].isAppleLogin = (getUserAuthResult && getUserAuthResult.length > 0 && getUserAuthResult[0].authProviderId == 3) ? true : false;

                                        result[0].userWalletAmount = 0;
                                        let getUserWalletSql = `SELECT * FROM userwallets WHERE userId = ` + result[0].id;
                                        let getUserWalletResult = await header.query(getUserWalletSql);
                                        if (getUserWalletResult && getUserWalletResult.length > 0) {
                                            result[0].userWalletAmount = getUserWalletResult[0].amount
                                        }

                                        //if (req.body.isSignup) {

                                        let adminUserSql = `SELECT * FROM users where id IN(select userId from userroles where (roleId = 1 OR roleId = 3)) AND isActive  = true AND isDelete = false`;
                                        let adminUserResult = await header.query(adminUserSql);
                                        if (adminUserResult && adminUserResult.length > 0) {
                                            for (let a = 0; a < adminUserResult.length; a++) {
                                                if (adminUserResult[a].isReceiveMail) {
                                                    let resultEmail = await sendEmail(config.emailMatrimonyNewUserRegister.fromName + ' <' + config.emailMatrimonyNewUserRegister.fromEmail + '>'
                                                        , [adminUserResult[a].email]
                                                        , config.emailMatrimonyNewUserRegister.subject
                                                        , ""
                                                        , config.emailMatrimonyNewUserRegister.html
                                                            .replace("[User's Full Name]", result[0].firstName + " " + result[0].lastName)
                                                            .replace("[User's Contact No]", result[0].contactNo)
                                                            .replace("[User's Email Address]", result[0].email)
                                                        , null, null);
                                                    console.log(resultEmail)
                                                }
                                                if (adminUserResult[a].isReceiveNotification) {
                                                    let deviceDetailSql = `SELECT * FROM userdevicedetail WHERE userId = ` + adminUserResult[a].id + ` AND fcmToken IS NOT NULL`;
                                                    let deviceDetailResult = await header.query(deviceDetailSql);
                                                    if (deviceDetailResult && deviceDetailResult.length > 0) {
                                                        let title = "New User Register";
                                                        let description = "New User " + result[0].firstName + " " + result[0].lastName + " registered in system. Please verify document";
                                                        let notificationSql = `INSERT INTO usernotifications(userId, title, message, bodyJson, imageUrl, createdBy, modifiedBy)
                                                    VALUES(` + adminUserResult[a].id + `,'` + title + `', '` + description + `', null, null, ` + authorizationResult.currentUser.id + `, ` + authorizationResult.currentUser.id + `)`
                                                        let notificationResult = await header.query(notificationSql);

                                                        await notificationContainer.sendMultipleNotification([deviceDetailResult[0].fcmToken], null, title, description, '', null, null, 0);
                                                        console.log("Send" + deviceDetailResult[0].fcmToken);
                                                    }
                                                }
                                            }
                                        }
                                        //}



                                        await header.commit();
                                        let successResult = new ResultSuccess(200, true, 'Update User Personal Detail', result, 1, authorizationResult.token);
                                        return res.status(200).send(successResult);
                                    } else {
                                        await header.rollback();
                                        let errorResult = new ResultError(400, true, "users.updateUserProfileDetail() Error", new Error('Error While Updating Data'), '');
                                        next(errorResult);
                                    }
                                } else {
                                    await header.rollback();
                                    let errorResult = new ResultError(400, true, "users.updateUserProfileDetail() Error", new Error('Error While Updating Data'), '');
                                    next(errorResult);
                                }
                            } else {
                                await header.rollback();
                                let errorResult = new ResultError(400, true, "users.updateUserProfileDetail() Error", new Error('Error While Updating Data'), '');
                                next(errorResult);
                            }
                        } else {
                            let insertAddress = `INSERT INTO addresses(addressLine1, addressLine2, pincode, cityId, districtId, stateId, countryId, countryName, stateName, cityName, latitude, longitude
                            , createdBy, modifiedBy) VALUES('` + req.body.addressLine1 + `','` + req.body.addressLine2 + `','` + req.body.pincode + `', ` + (req.body.cityId ? req.body.cityId : null) + `
                            , ` + (req.body.districtId ? req.body.districtId : null) + `, ` + (req.body.stateId ? req.body.stateId : null) + `, ` + (req.body.countryId ? req.body.countryId : null) + `
                            , '` + req.body.countryName + `','` + req.body.stateName + `','` + req.body.cityName + `', ` + req.body.latitude + `, ` + req.body.longitude + `,` + userId + `,` + userId + `)`;
                            let addressResult = await header.query(insertAddress);
                            if (addressResult && addressResult.insertId > 0) {
                                req.body.addressId = addressResult.insertId;
                                let insertSql = `INSERT INTO userpersonaldetail(userId, addressId, religionId, communityId, maritalStatusId, occupationId, educationId, subCommunityId, dietId, annualIncomeId, heightId, birthDate
                                , languages, eyeColor, businessName, companyName, employmentTypeId, expectation, aboutMe, createdBy, modifiedBy, weight, profileForId) VALUES(` + req.body.id + `,` + req.body.addressId + `,` + req.body.religionId + `
                                ,` + req.body.communityId + `,` + req.body.maritalStatusId + `,` + req.body.occupationId + `,` + req.body.educationId + `,` + req.body.subCommunityId + `,` + req.body.dietId + `
                                ,` + req.body.annualIncomeId + `,` + req.body.heightId + `,'` + bDate + `','` + req.body.languages + `','` + req.body.eyeColor + `', '` + req.body.businessName + `', '` + req.body.companyName + `'
                                , ` + req.body.employmentTypeId + `, '` + req.body.expectation + `', '` + req.body.aboutMe + `',` + userId + `,` + userId + `,` + req.body.weight + `,` + req.body.profileForId + `)`;
                                result = await header.query(insertSql);
                                if (result && result.affectedRows > 0) {

                                    let flagError = false;
                                    let checkRewardSql = `SELECT * FROM systemflags WHERE id IN(42,43)`;
                                    let checkRewardResult = await header.query(checkRewardSql);
                                    if (checkRewardResult && checkRewardResult.length > 0) {
                                        let ind = checkRewardResult.findIndex((c: any) => c.value == '1' && c.id == 42);
                                        let amount = parseFloat(checkRewardResult.find((c: any) => c.id == 43).value);
                                        if (ind >= 0) {
                                            //Insert Wallet User History and Insert/Update User Wallet
                                            let referalUserSql = `Select referalUserId from users where id = ` + req.body.id;
                                            let referalUserResult = await header.query(referalUserSql);
                                            if (referalUserResult && referalUserResult.length > 0 && referalUserResult[0].referalUserId != null) {
                                                let checkUserWalletSql = `SELECT * FROM userwallets WHERE userId = ` + referalUserResult[0].referalUserId;
                                                // let checkUserWalletSql = `SELECT * FROM userwallets WHERE userId = (select referalUserId from users where id=` + userId + `)`;

                                                let checkUserWalletResult = await header.query(checkUserWalletSql);
                                                if (checkUserWalletResult && checkUserWalletResult.length > 0) {
                                                    let lAmt = checkUserWalletResult[0].amount + amount;

                                                    let userWalletSql = `UPDATE userwallets SET amount = ` + lAmt + `, modifiedBy = ` + userId + `, modifiedDate = CURRENT_TIMESTAMP() WHERE id = ` + checkUserWalletResult[0].id;
                                                    let result = await header.query(userWalletSql);
                                                    if (result && result.affectedRows >= 0) {
                                                        let userWalletId = checkUserWalletResult[0].id;
                                                        let userWalletHistorySql = `INSERT INTO userwallethistory(userWalletId, amount, isCredit, transactionDate, remark, createdBy, modifiedBy) 
                                                    VALUES(`+ userWalletId + `,` + amount + `, 1, ?, 'Amount credited via refered user',` + userId + `,` + userId + ` )`;
                                                        result = await header.query(userWalletHistorySql, [new Date()]);
                                                        if (result && result.insertId > 0) {

                                                        } else {
                                                            flagError = true;
                                                            await header.rollback();
                                                            let errorResult = new ResultError(400, true, "users.updateUserProfileDetail() Error", new Error('Error While Inserting Data'), '');
                                                            next(errorResult);
                                                        }
                                                    } else {
                                                        flagError = true;
                                                        await header.rollback();
                                                        let errorResult = new ResultError(400, true, "users.updateUserProfileDetail() Error", new Error('Error While Inserting Data'), '');
                                                        next(errorResult);
                                                    }

                                                } else {
                                                    let userWalletSql = `INSERT INTO userwallets(userId, amount, createdBy, modifiedBy) VALUES(` + req.body.id + `,` + amount + `,` + userId + `,` + userId + `)`;
                                                    let result = await header.query(userWalletSql);
                                                    if (result && result.insertId > 0) {
                                                        let userWalletId = result.insertId;
                                                        let userWalletHistorySql = `INSERT INTO userwallethistory(userWalletId, amount, isCredit, transactionDate, remark, createdBy, modifiedBy) 
                                                    VALUES(`+ userWalletId + `,` + amount + `, 1, ?, 'Amount credited via refered user',` + userId + `,` + userId + ` )`;
                                                        result = await header.query(userWalletHistorySql, [new Date()]);
                                                        if (result && result.insertId > 0) {

                                                        } else {
                                                            flagError = true;
                                                            await header.rollback();
                                                            let errorResult = new ResultError(400, true, "users.updateUserProfileDetail() Error", new Error('Error While Inserting Data'), '');
                                                            next(errorResult);
                                                        }
                                                    } else {
                                                        flagError = true;
                                                        await header.rollback();
                                                        let errorResult = new ResultError(400, true, "users.updateUserProfileDetail() Error", new Error('Error While Inserting Data'), '');
                                                        next(errorResult);
                                                    }
                                                }

                                            } else {

                                            }

                                        }
                                    }


                                    if (!flagError) {


                                        let sql = `SELECT u.id, u.firstName, u.middleName, u.lastName, u.gender, u.email, u.contactNo
                                    , upd.birthDate, upd.languages, upd.eyeColor, upd.expectation, upd.aboutMe, upd.weight, upd.profileForId, pf.name as profileForName
                                    , img.imageUrl, r.name as religion, ms.name as maritalStatus, c.name as community, o.name as occupation, e.name as education, sc.name as subCommunity
                                , ai.value as annualIncome, d.name as diet, h.name as height
                                , addr.addressLine1, addr.addressLine2, addr.pincode, addr.cityId, addr.districtId, addr.stateId, addr.countryId
                                , cit.name as cityName, ds.name as districtName, st.name as stateName, cou.name as countryName
                                , em.name as employmentType, DATE_FORMAT(FROM_DAYS(DATEDIFF(now(),upd.birthDate)), '%Y')+0 AS age
                                , addr.latitude, addr.longitude
                                FROM users u
                                LEFT JOIN userroles ur ON ur.userId = u.id
                                LEFT JOIN images img ON img.id = u.imageId
                                LEFT JOIN userpersonaldetail upd ON upd.userId = u.id
                                LEFT JOIN religion r ON r.id = upd.religionId
                                LEFT JOIN maritalstatus ms ON ms.id = upd.maritalStatusId
                                LEFT JOIN community c ON c.id = upd.communityId
                                LEFT JOIN occupation o ON o.id = upd.occupationId
                                LEFT JOIN education e ON e.id = upd.educationId
                                LEFT JOIN subcommunity sc ON sc.id = upd.subCommunityId
                                LEFT JOIN annualincome ai ON ai.id = upd.annualIncomeId
                                LEFT JOIN diet d ON d.id = upd.dietId
                                LEFT JOIN height h ON h.id = upd.heightId
                                LEFT JOIN addresses addr ON addr.id = upd.addressId
                                LEFT JOIN cities cit ON addr.cityId = cit.id
                                LEFT JOIN districts ds ON addr.districtId = ds.id
                                LEFT JOIN state st ON addr.stateId = st.id
                                LEFT JOIN countries cou ON addr.countryId = cou.id
                                LEFT JOIN employmenttype em ON em.id = upd.employmenttypeId
                                LEFT JOIN profilefor pf ON pf.id = upd.profileForId
                                 WHERE ur.roleId = 2 AND u.id = ` + req.body.id;
                                        let result = await header.query(sql);

                                        // let adminUserSql = `SELECT u.* FROM users u INNER JOIN userroles ur ON ur.userId = u.id WHERE (ur.roleId = 1 OR ur.roleId = 3) AND u.isActive && u.isReceiveMail && !u.isDelete`
                                        // let adminUserResult = await header.query(adminUserSql);
                                        // let emails = [];
                                        // if (adminUserResult && adminUserResult.length > 0) {
                                        //     for (let i = 0; i < adminUserResult.length; i++) {
                                        //         if (adminUserResult[i].email)
                                        //             emails.push(adminUserResult[i].email)
                                        //     }

                                        // }
                                        // let resultEmail = await sendEmail(config.emailMatrimonyNewUserRegister.fromName + ' <' + config.emailMatrimonyNewUserRegister.fromEmail + '>'
                                        //     , emails
                                        //     , config.emailMatrimonyNewUserRegister.subject
                                        //     , ""
                                        //     , config.emailMatrimonyNewUserRegister.html
                                        //         .replace("[User's Full Name]", result[0].firstName + " " + result[0].lastName)
                                        //         .replace("[User's Contact No]", result[0].contactNo)
                                        //         .replace("[User's Email Address]", result[0].email)
                                        //     , null, null);

                                        if (result && result.length > 0) {
                                            result[0].isVerified = false;
                                            let isVerified = true;
                                            let documentsSql = `SELECT ud.*, dt.name as documentTypeName FROM userdocument ud INNER JOIN documenttype dt ON dt.id = ud.documentTypeId WHERE userId = ` + result[0].id;
                                            let documentsResult = await header.query(documentsSql);
                                            result[0].userDocuments = documentsResult;
                                            if (documentsResult && documentsResult.length > 0) {
                                                for (let j = 0; j < documentsResult.length; j++) {
                                                    if (documentsResult[j].isRequired && !documentsResult[j].isVerified) {
                                                        isVerified = false;
                                                    }
                                                }
                                            } else {
                                                isVerified = false;
                                            }
                                            result[0].isVerifiedProfile = isVerified;

                                            result[0].totalView = 0;
                                            result[0].todayView = 0;
                                            let totalViewSql = `SELECT COUNT(id) as totalView FROM userviewprofilehistories WHERE userId = ` + req.body.id;
                                            let totalViewResult = await header.query(totalViewSql);
                                            if (totalViewResult && totalViewResult.length > 0) {
                                                result[0].totalView = totalViewResult[0].totalView
                                            }
                                            let todayViewSql = `SELECT COUNT(id) as totalView FROM userviewprofilehistories WHERE userId = ` + req.body.id + ` AND DATE(transactionDate) = DATE(CURRENT_TIMESTAMP())`;
                                            let todayViewResult = await header.query(todayViewSql);
                                            if (todayViewResult && todayViewResult.length > 0) {
                                                result[0].todayView = todayViewResult[0].totalView
                                            }

                                            let userflagvalues = `SELECT ufv.*, uf.flagName, uf.displayName FROM userflagvalues ufv
                                            LEFT JOIN userflags uf ON uf.id = ufv.userFlagId
                                            WHERE ufv.userId = ` + req.body.id;
                                            result[0].userFlags = await header.query(userflagvalues);

                                            let getUserAuthSql = `SELECT * FROM userauthdata WHERE userId = ` + req.body.id;
                                            let getUserAuthResult = await header.query(getUserAuthSql)
                                            result[0].isOAuth = (getUserAuthResult && getUserAuthResult.length > 0) ? true : false;
                                            result[0].isAppleLogin = (getUserAuthResult && getUserAuthResult.length > 0 && getUserAuthResult[0].authProviderId == 3) ? true : false;

                                            result[0].userWalletAmount = 0;
                                            let getUserWalletSql = `SELECT * FROM userwallets WHERE userId = ` + result[0].id;
                                            let getUserWalletResult = await header.query(getUserWalletSql);
                                            if (getUserWalletResult && getUserWalletResult.length > 0) {
                                                result[0].userWalletAmount = getUserWalletResult[0].amount
                                            }

                                            if (req.body.isSignup) {

                                                let adminUserSql = `SELECT * FROM users where id IN(select userId from userroles where (roleId = 1 OR roleId = 3)) AND isActive  = true AND isDelete = false`;
                                                let adminUserResult = await header.query(adminUserSql);
                                                if (adminUserResult && adminUserResult.length > 0) {
                                                    for (let a = 0; a < adminUserResult.length; a++) {
                                                        if (adminUserResult[a].isReceiveMail) {
                                                            let resultEmail = await sendEmail(config.emailMatrimonyNewUserRegister.fromName + ' <' + config.emailMatrimonyNewUserRegister.fromEmail + '>'
                                                                , [adminUserResult[a].email]
                                                                , config.emailMatrimonyNewUserRegister.subject
                                                                , ""
                                                                , config.emailMatrimonyNewUserRegister.html
                                                                    .replace("[User's Full Name]", result[0].firstName + " " + result[0].lastName)
                                                                    .replace("[User's Contact No]", result[0].contactNo)
                                                                    .replace("[User's Email Address]", result[0].email)
                                                                , null, null);
                                                            console.log(resultEmail)
                                                        }
                                                        if (adminUserResult[a].isReceiveNotification) {
                                                            let deviceDetailSql = `SELECT * FROM userdevicedetail WHERE userId = ` + adminUserResult[a].id + ` AND fcmToken IS NOT NULL`;
                                                            let deviceDetailResult = await header.query(deviceDetailSql);
                                                            if (deviceDetailResult && deviceDetailResult.length > 0) {
                                                                let title = "New User Register";
                                                                let description = "New User " + result[0].firstName + " " + result[0].lastName + " registered in system. Please verify document";
                                                                let notificationSql = `INSERT INTO usernotifications(userId, title, message, bodyJson, imageUrl, createdBy, modifiedBy)
                                                    VALUES(` + adminUserResult[a].id + `,'` + title + `', '` + description + `', null, null, ` + authorizationResult.currentUser.id + `, ` + authorizationResult.currentUser.id + `)`
                                                                let notificationResult = await header.query(notificationSql);

                                                                await notificationContainer.sendMultipleNotification([deviceDetailResult[0].fcmToken], null, title, description, '', null, null, 0);
                                                                console.log("Send" + deviceDetailResult[0].fcmToken);
                                                            }
                                                        }
                                                    }
                                                }
                                            }

                                            await header.commit();
                                            let successResult = new ResultSuccess(200, true, 'Insert User Personal Detail', result, 1, authorizationResult.token);
                                            return res.status(200).send(successResult);
                                        } else {
                                            await header.rollback();
                                            let errorResult = new ResultError(400, true, "users.updateUserProfileDetail() Error", new Error('Error While Inserting Data'), '');
                                            next(errorResult);
                                        }
                                    }
                                } else {
                                    await header.rollback();
                                    let errorResult = new ResultError(400, true, "users.updateUserProfileDetail() Error", new Error('Error While Inserting Data'), '');
                                    next(errorResult);
                                }
                            } else {
                                await header.rollback();
                                let errorResult = new ResultError(400, true, "users.updateUserProfileDetail() Error", new Error('Error While Inserting Data'), '');
                                next(errorResult);
                            }
                        }
                    } else {
                        await header.rollback();
                        let errorResult = new ResultError(400, true, "users.updateUserProfileDetail() Error", new Error('Error While Updating Data'), '');
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
        let errorResult = new ResultError(500, true, 'users.updateUserProfileDetail() Exception', error, '');
        next(errorResult);
    }
}

const deleteAccount = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Delete Account');
        let requiredFields = [''];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let currentUser = authorizationResult.currentUser;
                let userId = currentUser ? currentUser.id : 0;
                await header.beginTransaction()
                let deleteQueries = [`DELETE FROM feedback WHERE createdBy = ` + userId,

                `DELETE FROM successstories WHERE createdBy = ` + userId,
                `DELETE FROM successstories WHERE userId = ` + userId,
                `DELETE FROM successstories WHERE partnerUserId = ` + userId,
                `DELETE FROM userauthdata WHERE userId = ` + userId,
                `DELETE FROM userblock WHERE userId = ` + userId,
                `DELETE FROM userblock WHERE userBlockId = ` + userId,
                `DELETE FROM userblockrequest WHERE userId = ` + userId,
                `DELETE FROM userblockrequest WHERE blockRequestUserId = ` + userId,
                `DELETE FROM userchat WHERE userId = ` + userId,
                `DELETE FROM userchat WHERE partnerId = ` + userId,
                `DELETE FROM userdevicedetail WHERE userId =` + userId,
                `DELETE FROM userdocument WHERE userId = ` + userId,
                `DELETE FROM userfavourites WHERE userId = ` + userId,
                `DELETE FROM userfavourites WHERE favUserId = ` + userId,
                `DELETE FROM userflagvalues WHERE userId = ` + userId,
                `DELETE FROM usernotifications WHERE userId = ` + userId,
                `DELETE FROM userpackage WHERE userId = ` + userId,
                `DELETE FROM userpersonaldetail WHERE userId = ` + userId,
                `DELETE FROM userproposals WHERE userId = ` + userId,
                `DELETE FROM userproposals WHERE proposalUserId = ` + userId,
                `DELETE FROM userrefreshtoken WHERE userId = ` + userId,
                `DELETE FROM userroles WHERE userId =` + userId,
                `DELETE FROM usertokens WHERE userId = ` + userId,
                `DELETE FROM userviewprofilehistories WHERE userId =` + userId,
                `DELETE FROM userviewprofilehistories WHERE viewProfileByUserId =` + userId,
                `DELETE FROM userwallethistory WHERE createdBy =` + userId,
                `DELETE FROM userwallets WHERE userId = ` + userId,
                `DELETE FROM payment WHERE createdBy = ` + userId,
                `DELETE FROM addresses WHERE createdBy = ` + userId,
                `DELETE FROM users WHERE id = ` + userId,
                `DELETE FROM images WHERE createdBy = ` + userId
                ];
                let result;
                for (let index = 0; index < deleteQueries.length; index++) {
                    result = await header.query(deleteQueries[index]);

                }
                // let sql = `CALL deleteUserAccount(` + userId + `)`;
                // let result = await header.query(sql);
                if (result) {
                    await header.commit();
                    let successResult = new ResultSuccess(200, true, 'Delete User Account Successfully', result, result.length, authorizationResult.token);
                    return res.status(200).send(successResult);
                }
                // if (result && result.length >= 0) {
                //     let successResult = new ResultSuccess(200, true, 'Delete User Account Successfully', result, result.length, authorizationResult.token);
                //     return res.status(200).send(successResult);
                // } else {
                //     let successResult = new ResultSuccess(200, true, ' Successfully', [], 0, authorizationResult.token);
                //     return res.status(200).send(successResult);
                // }
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
        let errorResult = new ResultError(500, true, 'users.getMostViewedApplicant() Exception', error, '');
        next(errorResult);
    }
}

export default {
    verifyEmailContact, signUp, login, checkContactNoExist, registerViaPhone, getMasterData, updateUserProfilePic, getAllUsers, viewUserDetail, updateUserProfileDetail, forgotPassword
    , verifyforgotPasswordLink, resetPassword, changePassword, changeContact, changeEmail, searchUser, updateUserFlagValues, validateAuthToken, getNearestApplicant, getMostViewedApplicant
    , completeUserProfile, deleteAccount
};