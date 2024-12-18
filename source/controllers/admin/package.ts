import { NextFunction, Request, Response } from 'express';
import logging from "../../config/logging";
import config from "../../config/config";
import header from "../../middleware/apiHeader";
import { ResultSuccess } from '../../classes/response/resultsuccess';
import { ResultError } from '../../classes/response/resulterror';

const mysql = require('mysql');
const util = require('util');
const fs = require('fs');

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

const NAMESPACE = 'Package';

const getpackage = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Package');
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) {
            let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
            let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
            let result;
            // let countSql = "SELECT COUNT(*) as totalCount  FROM timeduration";
            // let countResult = await header.query(countSql);
            // let sql = `SELECT * FROM timeduration WHERE isDelete = 0 ORDER BY value ASC`;
            // result = await header.query(sql);
            // if (result) {
            //     if (result && result.length > 0) {
            //         for (let y = 0; y < result.length; y++) {
            //             sql = `SELECT p.* , pd.id as packageDurationId, pd.timeDurationId, td.value, pd.discount FROM package p
            //             LEFT JOIN packageduration pd ON pd.packageId = p.id
            //             LEFT JOIN timeduration td ON td.id = pd.timeDurationId
            //             WHERE pd.timeDurationId = ` + result[y].id;
            //             if (startIndex != null && fetchRecord != null) {
            //                 sql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
            //             }
            //             result[y].package = await header.query(sql);
            //             let packageData = result[y].package;
            //             if (packageData) {
            //                 if (packageData && packageData.length > 0) {
            //                     for (let index = 0; index < packageData.length; index++) {
            //                         sql = `SELECT packagefacility.*, pf.name FROM packagefacility
            //                         LEFT JOIN premiumfacility pf ON pf.id = packagefacility.premiumFacilityId
            //                          WHERE packageId = ` + packageData[index].id;
            //                         result[y].package[index].facility = await header.query(sql);

            //                         // sql = `SELECT * FROM packageduration WHERE packageId = ` + result[index].id;
            //                         // result[index].duration = await query(sql);
            //                     }
            //                 }
            //             }
            //         }
            //     }
            //     let successResult = new ResultSuccess(200, true, 'Get Package Successfully', result, countResult[0].totalCount, authorizationResult.token);
            //     return res.status(200).send(successResult);
            // } else {
            //     let errorResult = new ResultError(400, true, "package.getpackage() Error", new Error('Error While Getting Data'), '');
            //     next(errorResult);
            // }

            let sql = `SELECT * FROM package ORDER BY weightage`;
            result = await header.query(sql);
            if (result && result.length > 0) {
                for (let i = 0; i < result.length; i++) {
                    let packageSql = `SELECT p.* , pd.id as packageDurationId, pd.timeDurationId, td.value, pd.discount FROM package p
                    LEFT JOIN packageduration pd ON pd.packageId = p.id
                    LEFT JOIN timeduration td ON td.id = pd.timeDurationId
                    WHERE p.id = ` + result[i].id;
                    result[i].package = await header.query(packageSql);
                    if (result[i].package && result[i].package.length > 0) {
                        for (let j = 0; j < result[i].package.length; j++) {
                            let facilitySql = `SELECT packagefacility.*, pf.name FROM packagefacility
                                    LEFT JOIN premiumfacility pf ON pf.id = packagefacility.premiumFacilityId
                                     WHERE packageId = ` + result[i].package[j].id;
                            result[i].package[j].facility = await header.query(facilitySql);
                        }
                    }
                }
                let successResult = new ResultSuccess(200, true, 'Get Package Successfully', result, result.length, authorizationResult.token);
                return res.status(200).send(successResult);
            } else {
                let errorResult = new ResultError(400, true, "package.getpackage() Error", new Error('Error While Getting Data'), '');
                next(errorResult);
            }
        } else {
            let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'package.getpackage() Exception', error, '');
        next(errorResult);
    }
};

const insertPackage = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Inserting Updating Premiun Facility');
        let requiredFields = ['name', 'baseAmount', 'weightage', 'facility', 'duration'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let currentUser = authorizationResult.currentUser;
                let userId = currentUser.id;
                let result;
                await header.beginTransaction();
                let checkNameSql = `SELECT * FROM package WHERE LOWER(name) = LOWER('` + req.body.name + `')`;
                let checkNameResult = await header.query(checkNameSql);
                if (checkNameResult && checkNameResult.length > 0) {                    
                    let packageId = checkNameResult[0].id;
                    if (req.body.duration && req.body.duration.length > 0) {
                        for (let j = 0; j < req.body.duration.length; j++) {
                            let sql = `INSERT INTO packageduration(packageId, timeDurationId, discount, createdBy, modifiedBy) VALUES (` + packageId + `,` + req.body.duration[j].timeDurationId + `, ` + req.body.duration[j].discount + `,` + userId + `,` + userId + `)`
                            result = await header.query(sql);
                        }
                    }
                    await header.commit();
                    let successResult = new ResultSuccess(200, true, 'Insert Package', result, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let checkSql = `SELECT * FROM package WHERE weightage = ` + req.body.weightage;
                    let checkResult = await header.query(checkSql);
                    if (checkResult && checkResult.length > 0) {
                        await header.rollback();
                        let errorResult = new ResultError(203, true, "Same Weightage Package already available", new Error('Same Weightage Package already available'), '');
                        next(errorResult);
                    } else {
                        let sql = `INSERT INTO package (name, baseAmount, weightage, createdBy, modifiedBy) VALUES ('` + req.body.name + `','` + req.body.baseAmount + `', ` + req.body.weightage + `,` + userId + `,` + userId + `)`;
                        result = await header.query(sql);
                        if (result && result.affectedRows > 0) {
                            let packageId = result.insertId;
                            if (req.body.facility && req.body.facility.length > 0) {
                                for (let index = 0; index < req.body.facility.length; index++) {
                                    sql = `INSERT INTO packagefacility(packageId, premiumFacilityId, createdBy, modifiedBy) VALUES (` + packageId + `, ` + req.body.facility[index].premiumFacilityId + `,` + userId + `,` + userId + `)`
                                    result = await header.query(sql);
                                }
                            }
                            if (req.body.duration && req.body.duration.length > 0) {
                                for (let j = 0; j < req.body.duration.length; j++) {
                                    sql = `INSERT INTO packageduration(packageId, timeDurationId, discount, createdBy, modifiedBy) VALUES (` + packageId + `,` + req.body.duration[j].timeDurationId + `, ` + req.body.duration[j].discount + `,` + userId + `,` + userId + `)`
                                    result = await header.query(sql);
                                }
                            }
                            await header.commit();
                            let successResult = new ResultSuccess(200, true, 'Insert Package', result, 1, authorizationResult.token);
                            return res.status(200).send(successResult);

                        } else {
                            await header.rollback();
                            let errorResult = new ResultError(400, true, "package.insertPackage() Error", new Error('Error While Inserting Data'), '');
                            next(errorResult);
                        }

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
        let errorResult = new ResultError(500, true, 'package.insertPackage() Exception', error, '');
        next(errorResult);
    }
};

const updatePackage = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Inserting Updating Premiun Facility');
        let requiredFields = ['id', 'name', 'baseAmount', 'facility', 'discount', 'timeDurationId'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let currentUser = authorizationResult.currentUser;
                let userId = currentUser.id;
                let result;
                let packageId = req.body.id;
                let checkSql = `SELECT * FROM package WHERE id != ` + req.body.id + ` AND weightage = ` + req.body.weightage;
                let checkResult = await header.query(checkSql);
                if (checkResult && checkResult.length > 0) {
                    await header.rollback();
                    let errorResult = new ResultError(203, true, "Same Weightage Package already available", new Error('Same Weightage Package already available'), '');
                    next(errorResult);
                } else {
                    let sql = `UPDATE package SET name = '` + req.body.name + `', baseAmount = '` + req.body.baseAmount + `', weightage = ` + req.body.weightage + `, modifiedDate = CURRENT_TIMESTAMP(), modifiedBy = ` + userId + ` WHERE id = ` + req.body.id;
                    result = await header.query(sql);
                    if (result && result.affectedRows > 0) {
                        let pacfacility = await header.query(`SELECT * FROM packagefacility WHERE packageId = ` + req.body.id);
                        //let duration = await query(`SELECT * FROM packageduration WHERE packageId = ` + req.body.id);
                        if (req.body.facility && req.body.facility.length > 0) {
                            for (let index = 0; index < req.body.facility.length; index++) {
                                if (req.body.facility[index].id) {
                                    sql = `UPDATE packagefacility SET packageId = ` + packageId + `, premiumFacilityId =  ` + req.body.facility[index].premiumFacilityId + `, modifiedDate = CURRENT_TIMESTAMP(), modifiedBy = ` + userId + ` WHERE id = ` + req.body.facility[index].id;
                                    result = await header.query(sql);
                                    pacfacility = pacfacility.filter((i: any) => i.id != req.body.facility[index].id);
                                } else {
                                    sql = `INSERT INTO packagefacility(packageId, premiumFacilityId, createdBy, modifiedBy) VALUES (` + packageId + `, ` + req.body.facility[index].premiumFacilityId + `,` + userId + `,` + userId + `)`
                                    result = await header.query(sql);
                                }
                            }
                            if (pacfacility && pacfacility.length > 0) {
                                for (let j = 0; j < pacfacility.length; j++) {
                                    let deleteSql = `DELETE FROM packagefacility WHERE id = ` + pacfacility[j].id;
                                    result = await header.query(deleteSql);
                                }
                            }
                        }
                        // if (req.body.duration && req.body.duration.length > 0) {
                        //     for (let k = 0; k < req.body.duration.length; k++) {
                        if (req.body.discount) {
                            sql = `UPDATE packageduration SET discount = ` + req.body.discount + `, modifiedDate = CURRENT_TIMESTAMP() , modifiedBy = ` + userId + ` WHERE packageId = ` + req.body.id + ` AND timeDurationId = ` + req.body.timeDurationId;
                            result = await header.query(sql);
                            //duration = duration.filter((i: any) => i.id != req.body.duration[k].id);
                        }
                        //  else {
                        //     sql = `INSERT INTO packageduration(packageId, timeDurationId, discount, createdBy, modifiedBy) VALUES (` + packageId + `,` + req.body.duration[k].timeDurationId + `, ` + req.body.duration[k].discount + `,` + userId + `,` + userId + `)`
                        //     result = await query(sql);
                        // }
                        // }
                        // if (duration && duration.length > 0) {
                        //     for (let m = 0; m < duration.length; m++) {
                        //         let deleteSql = `DELETE FROM packagefacility WHERE id = ` + duration[m].id;
                        //         result = await query(deleteSql);
                        //     }
                        // }
                        // }
                        let successResult = new ResultSuccess(200, true, 'Update Package', result, 1, authorizationResult.token);
                        return res.status(200).send(successResult);

                    } else {
                        let errorResult = new ResultError(400, true, "package.updatePackage() Error", new Error('Error While Updating Data'), '');
                        next(errorResult);
                    }
                }
            } else {
                let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
                next(errorResult);
            }
        } else {
            let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'package.updatePackage() Exception', error, '');
        next(errorResult);
    }
}

const activeInactivePackage = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Active Inactive Package');
        let requiredFields = ['id'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let sql = `UPDATE package set isActive = !isActive WHERE id = ` + req.body.id + ``;
                let result = await header.query(sql);
                if (result && result.affectedRows > 0) {
                    let successResult = new ResultSuccess(200, true, 'Change Package Status', result, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                }
                else {
                    let errorResult = new ResultError(400, true, "package.activeInactivePackage() Error", new Error('Error While Change Package Status'), '');
                    next(errorResult);
                }
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
        let errorResult = new ResultError(500, true, 'package.activeInactivePackage() Exception', error, '');
        next(errorResult);
    }
};

const deletePackage = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Active Inactive Package');
        let requiredFields = ['id', 'packageDurationId'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let selectSql = `SELECT * FROM userpackage WHERE packageDurationId = ` + req.body.packageDurationId;
                let result = await header.query(selectSql);
                if (result && result.length > 0) {
                    result = 'You are not able to delete this package';
                    let successResult = new ResultSuccess(200, true, 'Delete Package', result, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let sql = `DELETE FROM packageduration WHERE id = ` + req.body.packageDurationId;
                    result = await header.query(sql);
                    let checkSql = `SELECT * FROM packageduration WHERE packageId = ` + req.body.id;
                    result = await header.query(checkSql);
                    if (result && result.length > 0) {
                        let successResult = new ResultSuccess(200, true, 'Delete Package', result, 1, authorizationResult.token);
                        return res.status(200).send(successResult);
                    } else {
                        sql = `DELETE FROM packagefacility WHERE packageId = ` + req.body.id;
                        result = await header.query(sql);
                        if (result && result.affectedRows >= 0) {
                            sql = `DELETE FROM package WHERE id = ` + req.body.id + ``;
                            result = await header.query(sql);
                            if (result && result.affectedRows >= 0) {
                                let successResult = new ResultSuccess(200, true, 'Delete Package', result, 1, authorizationResult.token);
                                return res.status(200).send(successResult);
                            }
                            else {
                                let errorResult = new ResultError(400, true, "package.deletePackage() Error", new Error('Error While Delete Package'), '');
                                next(errorResult);
                            }
                        }
                    }

                }
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
        let errorResult = new ResultError(500, true, 'package.deletePackage() Exception', error, '');
        next(errorResult);
    }
};

const getPackageName = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Package');
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) {
            let sql = `SELECT * FROM package WHERE isActive = true AND isDelete = false`;
            let result = await header.query(sql);
            let successResult = new ResultSuccess(200, true, 'Get Package Successfully', result, result.length, authorizationResult.token);
            return res.status(200).send(successResult);
        } else {
            let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'package.getPackageName() Exception', error, '');
        next(errorResult);
    }
}

export default { getpackage, insertPackage, updatePackage, activeInactivePackage, deletePackage, getPackageName };