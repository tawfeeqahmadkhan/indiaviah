import { NextFunction, Request, Response } from 'express';
import logging from "../../config/logging";
import config from "../../config/config";
import header from "../../middleware/apiHeader";
import { ResultSuccess } from '../../classes/response/resultsuccess';
import { ResultError } from '../../classes/response/resulterror';
import notificationContainer from './../notifications';

// const mysql = require('mysql');
// const util = require('util');

// let connection = mysql.createConnection({
//     host: config.mysql.host,
//     user: config.mysql.user,
//     password: config.mysql.password,
//     database: config.mysql.database
// });

// const query = util.promisify(connection.query).bind(connection);

const NAMESPACE = 'App Users';

const getAppUsers = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting App Users');
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) {
            let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
            let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
            let countSql = `SELECT COUNT(*) as totalCount FROM users
                            LEFT JOIN userroles ur ON ur.userId = users.id
                            WHERE users.isDelete = 0 AND ur.roleId = 2 AND users.firstName IS NOT NULL`;
            if (req.body.searchString) {
                if (!countSql.includes(` WHERE `)) {
                    countSql += ` WHERE `;
                } else {
                    countSql += ` AND `;
                }
                countSql += ` (users.firstName LIKE '%` + req.body.searchString + `%' OR users.lastName LIKE '%` + req.body.searchString + `%' OR users.email LIKE '%` + req.body.searchString + `%' OR users.contactNo LIKE '%` + req.body.searchString + `%' OR users.gender LIKE '%` + req.body.searchString + `%')`;
            }
            let countResult = await header.query(countSql);
            let sql = ` SELECT users.*,i.imageUrl as imageUrl, ur.roleId as roleId FROM users
                        LEFT JOIN userroles ur ON ur.userId = users.id
                        LEFT JOIN images i ON  i.id = users.imageId
                        WHERE users.isDelete = 0 AND ur.roleId = 2 AND users.firstName IS NOT NULL`;
            if (req.body.searchString) {
                if (!sql.includes(` WHERE `)) {
                    sql += ` WHERE `;
                } else {
                    sql += ` AND `;
                }
                sql += ` (users.firstName LIKE '%` + req.body.searchString + `%' OR users.lastName LIKE '%` + req.body.searchString + `%' OR users.email LIKE '%` + req.body.searchString + `%' OR users.contactNo LIKE '%` + req.body.searchString + `%' OR users.gender LIKE '%` + req.body.searchString + `%') `;
            }
            sql += ` ORDER BY users.id DESC`
            if (startIndex != null && fetchRecord != null) {
                sql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
            }
            let result = await header.query(sql);
            if (result) {
                for (let i = 0; i < result.length; i++) {
                    let documentsSql = `SELECT ud.*, dt.name as documentTypeName FROM userdocument ud INNER JOIN documenttype dt ON dt.id = ud.documentTypeId WHERE userId = ` + result[i].id;
                    let documentsResult = await header.query(documentsSql);
                    result[i].userDocuments = documentsResult;
                }
                let successResult = new ResultSuccess(200, true, 'Get App Users Successfully', result, countResult[0].totalCount, authorizationResult.token);
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
        let errorResult = new ResultError(500, true, 'appUsers.getAppUsers() Exception', error, '');
        next(errorResult);
    }
};

const viewAppUserPerDetail = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Proposal');
        let requiredFields = ['userId'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let userPerDetailSql = `SELECT u.id, u.firstName, u.middleName, u.lastName, u.gender, u.email, u.contactNo
                , upd.birthDate, upd.languages, upd.eyeColor, upd.weight, upd.profileForId, pf.name as profileForName
                , img.imageUrl, r.name as religion
                , ms.name as maritalStatus, c.name as community, o.name as occupation, e.name as education, sc.name as subCommunity, ai.value as annualIncome, cou.name as country, em.name
                , DATE_FORMAT(FROM_DAYS(DATEDIFF(now(),upd.birthDate)), '%Y')+0 AS Age FROM users u
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
                LEFT JOIN state st ON addr.stateId = st.id
                LEFT JOIN countries cou ON addr.countryId = cou.id
                LEFT JOIN employmenttype em ON em.id = upd.employmenttypeId
                LEFT JOIN profilefor pf ON pf.id = upd.profileForId
                WHERE ur.roleId = 2 AND u.id = ` + req.body.userId;
                let result = await header.query(userPerDetailSql);
                if (result) {
                    for (let i = 0; i < result.length; i++) {
                        let documentsSql = `SELECT ud.*, dt.name as documentTypeName FROM userdocument ud INNER JOIN documenttype dt ON dt.id = ud.documentTypeId WHERE userId = ` + req.body.userId;
                        let documentsResult = await header.query(documentsSql);
                        result[i].userDocuments = documentsResult;

                        result[i].userWalletAmount = 0;
                        let getUserWalletSql = `SELECT * FROM userwallets WHERE userId = ` + result[i].id;
                        let getUserWalletResult = await header.query(getUserWalletSql);
                        if (getUserWalletResult && getUserWalletResult.length > 0) {
                            result[i].userWalletAmount = getUserWalletResult[i].amount
                        }
                    }
                    let successResult = new ResultSuccess(200, true, 'Get App User Detail Successfully', result, result.length, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "appUsers.viewAppUserDetail() Error", new Error('Error While Getting Data'), '');
                    next(errorResult);
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
        let errorResult = new ResultError(500, true, 'appUsers.viewAppUserDetail() Exception', error, '');
        next(errorResult);
    }
};

const viewAppUserSendRequest = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Proposal');
        let requiredFields = ['userId'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
                let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
                let countSql = `SELECT count(id) as totalRecords FROM userproposals
                WHERE userId = ` + req.body.userId;
                let countResult = await header.query(countSql);
                let proSendReqSql = `SELECT up.*, u.firstName, u.lastName, u.gender, u.email, u.contactNo, img.imageUrl FROM userproposals up
                LEFT JOIN users u ON u.id = up.proposalUserId
                LEFT JOIN images img ON img.id = u.imageId
                WHERE up.isDelete = 0 And up.userId = ` + req.body.userId;
                if (startIndex != null && fetchRecord != null) {
                    proSendReqSql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
                }
                let result = await header.query(proSendReqSql);
                if (result) {
                    let successResult = new ResultSuccess(200, true, 'Get App User Detail Successfully', result, countResult[0].totalRecords, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "appUsers.viewAppUserDetail() Error", new Error('Error While Getting Data'), '');
                    next(errorResult);
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
        let errorResult = new ResultError(500, true, 'appUsers.viewAppUserDetail() Exception', error, '');
        next(errorResult);
    }
};

const viewAppUserGotRequest = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Proposal');
        let requiredFields = ['userId'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
                let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
                let countSql = `SELECT count(id) as totalRecords FROM userproposals
                WHERE proposalUserId = ` + req.body.userId;
                let countResult = await header.query(countSql);
                let propGotReqSql = `SELECT up.*, u.firstName, u.lastName, u.gender, u.email, u.contactNo, img.imageUrl FROM userproposals up
                LEFT JOIN users u ON u.id = up.userId
                LEFT JOIN images img ON img.id = u.imageId
                WHERE up.isDelete = 0 And up.proposalUserId = ` + req.body.userId;
                if (startIndex != null && fetchRecord != null) {
                    propGotReqSql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
                }
                let result = await header.query(propGotReqSql);
                if (result) {
                    let successResult = new ResultSuccess(200, true, 'Get App User Detail Successfully', result, countResult[0].totalRecords, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "appUsers.viewAppUserDetail() Error", new Error('Error While Getting Data'), '');
                    next(errorResult);
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
        let errorResult = new ResultError(500, true, 'appUsers.viewAppUserDetail() Exception', error, '');
        next(errorResult);
    }
};

const viewAppUserFavourites = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Proposal');
        let requiredFields = ['userId'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
                let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
                let countSql = `SELECT count(id) as totalRecords FROM userfavourites
                WHERE userId = ` + req.body.userId;
                let countResult = await header.query(countSql);
                let favSql = `SELECT uf.*, u.firstName, u.lastName, u.gender, u.email, u.contactNo, img.imageUrl FROM userfavourites uf
                LEFT JOIN users u ON u.id = uf.favUserId
                LEFT JOIN images img ON img.id = u.imageId
                WHERE uf.isDelete = 0 And uf.userId = ` + req.body.userId;
                if (startIndex != null && fetchRecord != null) {
                    favSql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
                }
                let result = await header.query(favSql);
                if (result) {
                    let successResult = new ResultSuccess(200, true, 'Get App User Detail Successfully', result, countResult[0].totalRecords, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "appUsers.viewAppUserDetail() Error", new Error('Error While Getting Data'), '');
                    next(errorResult);
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
        let errorResult = new ResultError(500, true, 'appUsers.viewAppUserDetail() Exception', error, '');
        next(errorResult);
    }
};

const viewBlockUser = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Proposal');
        let requiredFields = ['userId'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
                let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
                let countSql = `SELECT count(id) as totalRecords FROM userblock
                WHERE userId = ` + req.body.userId;
                let countResult = await header.query(countSql);
                let blockReqSql = `select ub.*,u.firstName, u.lastName, u.gender, u.email, u.contactNo, img.imageUrl from userblock ub 
                left join users u on u.id = ub.userblockId
                left join images img on u.imageId = img.id
                where userId = ` + req.body.userId;
                if (startIndex != null && fetchRecord != null) {
                    blockReqSql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
                }
                let result = await header.query(blockReqSql);
                if (result) {
                    let successResult = new ResultSuccess(200, true, 'Get App User Detail Successfully', result, countResult[0].totalRecords, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "appUsers.viewBlockUser() Error", new Error('Error While Getting Data'), '');
                    next(errorResult);
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
        let errorResult = new ResultError(500, true, 'appUsers.viewBlockUser() Exception', error, '');
        next(errorResult);
    }
};

const unblockUserRequest = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Updating User Block Request');
        let requiredFields = ['id', 'status'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let currentUser = authorizationResult.currentUser;
                let userId = currentUser.id;
                let result;
                let sql = `UPDATE userblockrequest SET status = ` + req.body.status + ` WHERE blockRequestUserId = ` + req.body.id;
                result = await header.query(sql);

                let updateSql = `UPDATE users SET isDisable = ` + req.body.status + `, modifiedDate = CURRENT_TIMESTAMP WHERE id =` + req.body.id;
                result = await header.query(updateSql);
                if (result && result.affectedRows > 0) {
                    let successResult = new ResultSuccess(200, true, 'Update User Block Request', result, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "userBlockRequest.updateUserBlockRequest() Error", new Error('Error While Updating Data'), '');
                    next(errorResult);
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
        let errorResult = new ResultError(500, true, 'userBlockRequest.updateUserBlockRequest() Exception', error, '');
        next(errorResult);
    }
};

const approveDocument = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Approve Document');
        let requiredFields = ['id', 'isVerified'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let currentUser = authorizationResult.currentUser;
                let userId = currentUser.id;
                let result;
                let updateSql = `UPDATE userdocument SET isVerified = ` + req.body.isVerified + `, modifiedDate = CURRENT_TIMESTAMP(), modifiedBy = ` + userId + ` WHERE id = ` + req.body.id;
                result = await header.query(updateSql);
                if (result && result.affectedRows > 0) {
                    let successResult = new ResultSuccess(200, true, 'Approve User Document', result, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "appUsers.approveDocument() Error", new Error('Error While Updating Data'), '');
                    next(errorResult);
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
        let errorResult = new ResultError(500, true, 'appUsers.approveDocument() Exception', error, '');
        next(errorResult);
    }
}

const getUserPackages = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Inserting Proposals');
        let requiredFields = [''];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let currentUser = authorizationResult.currentUser;
                let userId = currentUser.id;
                let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
                let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
                let countSql = `SELECT COUNT(up.id) as totalCount FROM  userpackage up
                LEFT JOIN package p on p.id= up.packageId
                LEFT join payment pay on pay.id= up.paymentId
                left join packageduration pd on pd.id = up.packageDurationId
                left join timeduration t on t.id = pd.timeDurationId
                INNER JOIN users u ON u.id = up.userId`
                if (req.body.userId) {
                    if (!countSql.includes(` WHERE `)) {
                        countSql += ` WHERE `;
                    } else {
                        countSql += ` AND `;
                    }
                    countSql += ` up.userId = ` + req.body.userId;
                }
                if (req.body.paymentStatus && req.body.paymentStatus != "All") {
                    if (!countSql.includes(` WHERE `)) {
                        countSql += ` WHERE `;
                    } else {
                        countSql += ` AND `;
                    }
                    countSql += ` pay.paymentStatus = '` + req.body.paymentStatus + `'`;
                }
                if (req.body.searchString) {
                    if (!countSql.includes(` WHERE `)) {
                        countSql += ` WHERE `;
                    } else {
                        countSql += ` AND `;
                    }
                    countSql += ` (p.name LIKE '%` + req.body.searchString + `%' OR  u.firstName LIKE '%` + req.body.searchString + `%' OR u.lastName LIKE '%` + req.body.searchString + `%' OR u.email LIKE '%` + req.body.searchString + `%' OR u.contactNo LIKE '%` + req.body.searchString + `%' OR u.gender LIKE '%` + req.body.searchString + `%') `;
                }
                let countResult = await header.query(countSql);

                let sql = `SELECT up.id, up.packageId,p.name as packageName,up.packageDurationId,up.startDate,up.endDate,up.netAmount,pay.paymentMode,pay.paymentStatus
                ,t.value, u.id as userId, u.firstName, u.lastName, u.contactNo, pay.id as paymentId FROM  userpackage up
                LEFT JOIN package p on p.id= up.packageId
                LEFT join payment pay on pay.id= up.paymentId
                left join packageduration pd on pd.id = up.packageDurationId
                left join timeduration t on t.id = pd.timeDurationId
                INNER JOIN users u ON u.id = up.userId`
                if (req.body.userId) {
                    if (!sql.includes(` WHERE `)) {
                        sql += ` WHERE `;
                    } else {
                        sql += ` AND `;
                    }
                    sql += ` up.userId = ` + req.body.userId;
                }
                if (req.body.paymentStatus && req.body.paymentStatus != "All") {
                    if (!sql.includes(` WHERE `)) {
                        sql += ` WHERE `;
                    } else {
                        sql += ` AND `;
                    }
                    sql += ` pay.paymentStatus = '` + req.body.paymentStatus + `'`;
                }
                if (req.body.searchString) {
                    if (!sql.includes(` WHERE `)) {
                        sql += ` WHERE `;
                    } else {
                        sql += ` AND `;
                    }
                    sql += ` (p.name LIKE '%` + req.body.searchString + `%' OR  u.firstName LIKE '%` + req.body.searchString + `%' OR u.lastName LIKE '%` + req.body.searchString + `%' OR u.email LIKE '%` + req.body.searchString + `%' OR u.contactNo LIKE '%` + req.body.searchString + `%' OR u.gender LIKE '%` + req.body.searchString + `%') `;
                }
                sql += ` order by up.id desc `
                if (!(req.body.packageStatus && req.body.packageStatus != "All")) {
                    if (startIndex != null && fetchRecord != null) {
                        sql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
                    }
                }
                let result = await header.query(sql);
                if (result && result.length >= 0) {
                    for (let i = 0; i < result.length; i++) {
                        result[i].status = "";
                        if (result[i].paymentStatus == "Pending") {
                            result[i].status = "Pending"
                        } else {
                            let userPackages = `SELECT up.*, p.name as packageName, td.id as timeDurationId, td.value, p.weightage FROM userpackage up
                            LEFT JOIN package p ON p.id = up.packageId
                            LEFT JOIN packageduration pd ON pd.id = up.packageDurationId
                            LEFT JOIN timeduration td ON td.id = pd.timeDurationId
                            WHERE DATE(up.startDate) <= DATE(CURRENT_TIMESTAMP()) AND DATE(up.endDate) >= DATE(CURRENT_TIMESTAMP())`;
                            if (req.body.userId) {
                                if (!userPackages.includes(` WHERE `)) {
                                    userPackages += ` WHERE `;
                                } else {
                                    userPackages += ` AND `;
                                }
                                userPackages += ` up.userId = ` + req.body.userId;
                            }
                            userPackages += ` order by p.weightage DESC `
                            let userPackage = await header.query(userPackages);
                            if (userPackage && userPackage.length > 0) {
                                for (let j = 0; j < userPackage.length; j++) {
                                    if (userPackage[0].id == result[i].id) {
                                        result[i].status = "Active";
                                    } else {
                                        result[i].status = "Override";
                                    }
                                }
                            }
                            if (new Date(result[i].endDate).getTime() < new Date().getTime()) {
                                result[i].status = "Expired";
                            } else if (new Date(result[i].startDate).getTime() > new Date().getTime()) {
                                result[i].status = "Upcomming";
                            }
                        }
                    }
                    let totalCount = 0;
                    if (req.body.packageStatus && req.body.packageStatus != "All") {
                        result = result.filter((c: any) => c.status == req.body.packageStatus);
                        totalCount = result.length;
                        result = result.slice(startIndex, startIndex + fetchRecord)
                    } else {
                        totalCount = countResult[0].totalCount;
                    }


                    let successResult = new ResultSuccess(200, true, 'Get Package of Users', result, totalCount, authorizationResult.token);

                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "appUsers.getUserPackages() Error", new Error('Error While Updating Data'), '');
                    next(errorResult);
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
        let errorResult = new ResultError(500, true, 'appUsers.getUserPackages() Exception', error, '');
        next(errorResult);
    }
}

const activeUserPackage = async (req: Request, res: Response, next: NextFunction) => {
    await header.beginTransaction();
    try {
        logging.info(NAMESPACE, 'Active Premium Account');
        let requiredFields = ['packageId', 'packageDurationId', 'userId', 'paymentId'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let currentUser = authorizationResult.currentUser;
                let userId = currentUser.id;
                let checkPaymentStatusSql = `UPDATE payment SET paymentRefrence = ` + (req.body.paymentRefrence ? `'` + req.body.paymentRefrence + `'` : null) + `, paymentStatus='Success' WHERE id = ` + req.body.paymentId;
                let result = await header.query(checkPaymentStatusSql);
                if (result && result.affectedRows >= 0) {
                    let getUserPackageSql = `SELECT up.*, p.weightage FROM userpackage up INNER JOIN package p ON p.id = up.packageId WHERE DATE(up.endDate) >= DATE(CURRENT_TIMESTAMP()) 
                    AND up.userId = ` + req.body.userId + ` ORDER BY up.endDate`;
                    let getUserPackageResult = await header.query(getUserPackageSql);
                    let currentPackageSql = `SELECT p.*, t.value as month FROM package p INNER JOIN packageduration pd ON pd.packageId = p.id INNER JOIN timeduration t on t.id = pd.timeDurationId WHERE pd.id=` + req.body.packageDurationId;
                    let currentPackageResult = await header.query(currentPackageSql);
                    if (getUserPackageResult && getUserPackageResult.length > 0 && currentPackageResult && currentPackageResult.length > 0) {
                        let filterData = getUserPackageResult.filter((c: any) => c.weightage >= currentPackageResult[0].weightage);
                        if (filterData && filterData.length > 0) {
                            //extend
                            let startDate = new Date(filterData[filterData.length - 1].endDate).getFullYear() + "-" + (new Date(filterData[filterData.length - 1].endDate).getMonth() + 1) + "-" + (new Date(filterData[filterData.length - 1].endDate).getDate() + 1) + " 00:00:00";
                            let eDt = new Date(new Date(startDate).setMonth(new Date(startDate).getMonth() + currentPackageResult[0].month));
                            let endDate = new Date(eDt).getFullYear() + "-" + (new Date(eDt).getMonth() + 1) + "-" + (new Date(eDt).getDate() - 1) + " 23:59:59";
                            let sql = `UPDATE userpackage SET startDate = ?, endDate = ?, modifiedBy = ` + userId + `, modifiedData = CURRENT_TIMESTAMP() WHERE id = ` + req.body.packageId;
                            result = await header.query(sql, [new Date(startDate), new Date(endDate)]);
                            if (result && result.affectedRows > 0) {
                                let userPackages = `SELECT up.*, p.name as packageName, td.id as timeDurationId, td.value, p.weightage FROM userpackage up
                                                    LEFT JOIN package p ON p.id = up.packageId
                                                    LEFT JOIN packageduration pd ON pd.id = up.packageDurationId
                                                    LEFT JOIN timeduration td ON td.id = pd.timeDurationId
                                                    WHERE up.userId = ` + req.body.userId + ` AND DATE(up.startDate) <= DATE(CURRENT_TIMESTAMP()) AND DATE(up.endDate) >= DATE(CURRENT_TIMESTAMP())
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
                                //result[0] = userPackage[0]

                                let fcmToken;
                                let customerFcmSql = "SELECT fcmToken FROM userdevicedetail WHERE userId = " + req.body.userId + " ORDER BY id DESC LIMIT 1";
                                let customerFcmResult = await header.query(customerFcmSql);
                                if (customerFcmResult && customerFcmResult.length > 0) {
                                    fcmToken = customerFcmResult[0].fcmToken;
                                }
                                if (fcmToken) {
                                    let title = "Purchased Package Activated";
                                    let description = "Your purchased package " + userPackage[0].packageName + " for " + userPackage[0].value + " month was approved by admin";
                                    let notificationRes = await notificationContainer.sendMultipleNotification([fcmToken], req.body.id, title, description, '', null, null, 1);
                                    let notificationSql = `INSERT INTO usernotifications(userId, title, message, bodyJson, imageUrl, createdBy, modifiedBy)
                                     VALUES(` + req.body.userId + `,'` + title + `', '` + description + `', null, null, ` + authorizationResult.currentUser.id + `, ` + authorizationResult.currentUser.id + `)`
                                    let notificationresult = await header.query(notificationSql);
                                    if (notificationresult && notificationresult.insertId > 0) {
                                        await header.commit();
                                        let successResult = new ResultSuccess(200, true, 'Save Premium Account', userPackage[0], 1, authorizationResult.token);
                                        return res.status(200).send(successResult);
                                    } else {
                                        await header.rollback();
                                        let errorResult = new ResultError(400, true, "favourites.addRemoveFavourite() Error", new Error('Error While Updating Data'), '');
                                        next(errorResult);
                                    }
                                } else {
                                    await header.commit();
                                    let successResult = new ResultSuccess(200, true, 'Save Premium Account', userPackage[0], 1, authorizationResult.token);
                                    return res.status(200).send(successResult);
                                }
                            } else {
                                await header.rollback();
                                let errorResult = new ResultError(400, true, "package.activeUserPackage() Error", new Error('Error While Updating Data'), '');
                                next(errorResult);
                            }
                        } else {
                            //overright
                            let startDate = new Date().getFullYear() + "-" + (new Date().getMonth() + 1) + "-" + new Date().getDate() + " 00:00:00";
                            let eDt = new Date(new Date(startDate).setMonth(new Date(startDate).getMonth() + currentPackageResult[0].month));
                            let endDate = new Date(eDt).getFullYear() + "-" + (new Date(eDt).getMonth() + 1) + "-" + (new Date(eDt).getDate() - 1) + " 23:59:59";
                            let sql = `UPDATE userpackage SET startDate = ?, endDate = ?, modifiedBy = ` + userId + `, modifiedData = CURRENT_TIMESTAMP() WHERE id = ` + req.body.packageId;
                            result = await header.query(sql, [new Date(startDate), new Date(endDate)]);
                            if (result && result.affectedRows > 0) {
                                let id = req.body.packageId;
                                let insertedPackageDurationSql = `SELECT t.* FROM timeduration t INNER JOIN packageduration pd ON pd.timeDurationId = t.id WHERE pd.id = ` + req.body.packageDurationId;
                                let insertedPackageDurationResult = await header.query(insertedPackageDurationSql);
                                let getFuturePackageSql = `SELECT up.*, t.value as month FROM userpackage up INNER JOIN packageduration pd ON pd.id = up.packageDurationId 
                            INNER JOIN timeduration t on t.id = pd.timeDurationId WHERE DATE(up.startDate)>DATE(CURRENT_TIMESTAMP()) AND up.id != ` + id;
                                let getFuturePackageResult = await header.query(getFuturePackageSql);
                                if (getFuturePackageResult && getFuturePackageResult.length > 0 && insertedPackageDurationResult && insertedPackageDurationResult.length > 0) {
                                    for (let i = 0; i < getFuturePackageResult.length; i++) {
                                        let sDt = new Date(endDate);
                                        let startDate = new Date(sDt).getFullYear() + "-" + (new Date(sDt).getMonth() + 1) + "-" + (new Date(sDt).getDate() + 1) + " 00:00:00";
                                        let eDt = new Date(new Date(startDate).setMonth(new Date(startDate).getMonth() + getFuturePackageResult[i].month));
                                        let endnDate = new Date(eDt).getFullYear() + "-" + (new Date(eDt).getMonth() + 1) + "-" + (new Date(eDt).getDate() - 1) + " 23:59:59";
                                        let updateUserPackageSql = `UPDATE userpackage SET startDate = ?, endDate = ?, modifiedBy = ` + userId + `, modifiedData = CURRENT_TIMESTAMP() WHERE id = ` + getFuturePackageResult[i].id;
                                        let updateUserPackageResult = await header.query(updateUserPackageSql, [startDate, endnDate]);
                                        if (updateUserPackageResult && updateUserPackageResult.affectedRows >= 0) {
                                        } else {
                                            await header.rollback();

                                            let errorResult = new ResultError(400, true, "package.activeUserPackage() Error", new Error('Error While Updating Data'), '');
                                            next(errorResult);
                                        }
                                    }
                                }

                                let userPackages = `SELECT up.*, p.name as packageName, td.id as timeDurationId, td.value, p.weightage FROM userpackage up
                            LEFT JOIN package p ON p.id = up.packageId
                            LEFT JOIN packageduration pd ON pd.id = up.packageDurationId
                            LEFT JOIN timeduration td ON td.id = pd.timeDurationId
                            WHERE up.userId = ` + req.body.userId + ` AND DATE(up.startDate) <= DATE(CURRENT_TIMESTAMP()) AND DATE(up.endDate) >= DATE(CURRENT_TIMESTAMP())
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
                                //result[0] = userPackage[0]

                                let fcmToken;
                                let customerFcmSql = "SELECT fcmToken FROM userdevicedetail WHERE userId = " + req.body.userId + " ORDER BY id DESC LIMIT 1";
                                let customerFcmResult = await header.query(customerFcmSql);
                                if (customerFcmResult && customerFcmResult.length > 0) {
                                    fcmToken = customerFcmResult[0].fcmToken;
                                }
                                if (fcmToken) {
                                    let title = "Purchased Package Activated";
                                    let description = "Your purchased package " + userPackage[0].packageName + " for " + userPackage[0].value + " month was approved by admin";
                                    let notificationRes = await notificationContainer.sendMultipleNotification([fcmToken], req.body.id, title, description, '', null, null, 1);
                                    let notificationSql = `INSERT INTO usernotifications(userId, title, message, bodyJson, imageUrl, createdBy, modifiedBy)
                                     VALUES(` + req.body.userId + `,'` + title + `', '` + description + `', null, null, ` + authorizationResult.currentUser.id + `, ` + authorizationResult.currentUser.id + `)`
                                    let notificationresult = await header.query(notificationSql);
                                    if (notificationresult && notificationresult.insertId > 0) {
                                        await header.commit();
                                        let successResult = new ResultSuccess(200, true, 'Save Premium Account', userPackage[0], 1, authorizationResult.token);
                                        return res.status(200).send(successResult);
                                    } else {
                                        await header.rollback();
                                        let errorResult = new ResultError(400, true, "favourites.addRemoveFavourite() Error", new Error('Error While Updating Data'), '');
                                        next(errorResult);
                                    }
                                } else {
                                    await header.commit();
                                    let successResult = new ResultSuccess(200, true, 'Save Premium Account', userPackage[0], 1, authorizationResult.token);
                                    return res.status(200).send(successResult);
                                }

                                // await header.commit();

                                // let successResult = new ResultSuccess(200, true, 'Save Premium Account', userPackage[0], 1, authorizationResult.token);
                                // return res.status(200).send(successResult);
                            } else {
                                await header.rollback();

                                let errorResult = new ResultError(400, true, "package.activeUserPackage() Error", new Error('Error While Updating Data'), '');
                                next(errorResult);
                            }
                        }
                    } else {
                        //insert
                        let startDate = new Date().getFullYear() + "-" + (new Date().getMonth() + 1) + "-" + new Date().getDate() + " 00:00:00";
                        let eDt = new Date(new Date(startDate).setMonth(new Date(startDate).getMonth() + currentPackageResult[0].month));
                        let endDate = new Date(eDt).getFullYear() + "-" + (new Date(eDt).getMonth() + 1) + "-" + (new Date(eDt).getDate() - 1) + " 23:59:59";
                        let sql = `UPDATE userpackage SET startDate = ?, endDate = ?, modifiedBy = ` + userId + `, modifiedData = CURRENT_TIMESTAMP() WHERE id = ` + req.body.packageId;
                        result = await header.query(sql, [new Date(startDate), new Date(endDate)]);
                        if (result && result.affectedRows > 0) {
                            let userPackages = `SELECT up.*, p.name as packageName, td.id as timeDurationId, td.value, p.weightage FROM userpackage up
                        LEFT JOIN package p ON p.id = up.packageId
                        LEFT JOIN packageduration pd ON pd.id = up.packageDurationId
                        LEFT JOIN timeduration td ON td.id = pd.timeDurationId
                        WHERE up.userId = ` + req.body.userId + ` AND DATE(up.startDate) <= DATE(CURRENT_TIMESTAMP()) AND DATE(up.endDate) >= DATE(CURRENT_TIMESTAMP())
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
                            //result[0] = userPackage[0];

                            let fcmToken;
                            let customerFcmSql = "SELECT fcmToken FROM userdevicedetail WHERE userId = " + req.body.userId + " ORDER BY id DESC LIMIT 1";
                            let customerFcmResult = await header.query(customerFcmSql);
                            if (customerFcmResult && customerFcmResult.length > 0) {
                                fcmToken = customerFcmResult[0].fcmToken;
                            }
                            if (fcmToken) {
                                let title = "Purchased Package Activated";
                                let description = "Your purchased package " + userPackage[0].packageName + " for " + userPackage[0].value + " month was approved by admin";
                                let notificationRes = await notificationContainer.sendMultipleNotification([fcmToken], req.body.id, title, description, '', null, null, 1);
                                let notificationSql = `INSERT INTO usernotifications(userId, title, message, bodyJson, imageUrl, createdBy, modifiedBy)
                                     VALUES(` + req.body.userId + `,'` + title + `', '` + description + `', null, null, ` + authorizationResult.currentUser.id + `, ` + authorizationResult.currentUser.id + `)`
                                let notificationresult = await header.query(notificationSql);
                                if (notificationresult && notificationresult.insertId > 0) {
                                    await header.commit();
                                    let successResult = new ResultSuccess(200, true, 'Save Premium Account', userPackage[0], 1, authorizationResult.token);
                                    return res.status(200).send(successResult);
                                } else {
                                    await header.rollback();
                                    let errorResult = new ResultError(400, true, "favourites.addRemoveFavourite() Error", new Error('Error While Updating Data'), '');
                                    next(errorResult);
                                }
                            } else {
                                await header.commit();
                                let successResult = new ResultSuccess(200, true, 'Save Premium Account', userPackage[0], 1, authorizationResult.token);
                                return res.status(200).send(successResult);
                            }


                            // await header.commit();

                            // let successResult = new ResultSuccess(200, true, 'Save Premium Account', userPackage[0], 1, authorizationResult.token);
                            // return res.status(200).send(successResult);
                        } else {
                            await header.rollback();

                            let errorResult = new ResultError(400, true, "package.activeUserPackage() Error", new Error('Error While Updating Data'), '');
                            next(errorResult);
                        }
                    }
                } else {
                    await header.rollback();

                    let errorResult = new ResultError(400, true, "package.activeUserPackage() Error", new Error('Error While Updating Data'), '');
                    next(errorResult);
                }
            } else {
                await header.rollback();

                let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
                next(errorResult);
            }
        }
        else {
            await header.rollback();

            let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
            next(errorResult);
        }
    }
    catch (error: any) {
        await header.rollback();

        let errorResult = new ResultError(500, true, 'package.activeUserPackage() Exception', error, '');
        next(errorResult);
    }
}

export default { getAppUsers, viewAppUserPerDetail, viewAppUserSendRequest, viewAppUserGotRequest, viewAppUserFavourites, unblockUserRequest, viewBlockUser, approveDocument, getUserPackages, activeUserPackage }