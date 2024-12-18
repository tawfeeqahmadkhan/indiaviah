import { NextFunction, Request, Response } from 'express';
import logging from "../../config/logging";
import config from "../../config/config";
import header from "../../middleware/apiHeader";
import { ResultSuccess } from '../../classes/response/resultsuccess';
import { ResultError } from '../../classes/response/resulterror';

const NAMESPACE = 'Coupons';

const getCoupons = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Coupon');
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) {
            let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
            let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
            let countSql = "SELECT COUNT(c.id) as totalCount  FROM coupons c ";
            if (req.body.searchString) {
                if (!countSql.includes(` WHERE `)) {
                    countSql += ` WHERE `;
                } else {
                    countSql += ` AND `;
                }
                countSql += ` (LOWER(c.name) LIKE '%` + req.body.searchString.toString().toLowerCase() + `%' OR LOWER(c.code) LIKE '%` + req.body.searchString.toString().toLowerCase() + `%') `;
            }
            if (req.body.isActive === true || req.body.isActive === false) {
                if (!countSql.includes(` WHERE `)) {
                    countSql += ` WHERE `;
                } else {
                    countSql += ` AND `;
                }
                countSql += ` c.isActive = ` + req.body.isActive;
            }

            let countResult = await header.query(countSql);
            let sql = `SELECT c.* FROM coupons c WHERE c.isDelete = 0 `;
            if (req.body.searchString) {
                if (!sql.includes(` WHERE `)) {
                    sql += ` WHERE `;
                } else {
                    sql += ` AND `;
                }
                sql += ` (LOWER(c.name) LIKE '%` + req.body.searchString.toString().toLowerCase() + `%' OR LOWER(c.code) LIKE '%` + req.body.searchString.toString().toLowerCase() + `%') `;
            }
            if (req.body.isActive === true || req.body.isActive === false) {
                if (!sql.includes(` WHERE `)) {
                    sql += ` WHERE `;
                } else {
                    sql += ` AND `;
                }
                sql += ` c.isActive = ` + req.body.isActive;
            }
            sql += ` ORDER BY id DESC `;
            if (startIndex != null && fetchRecord != null) {
                sql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
            }
            let result = await header.query(sql);
            if (result) {
                for (let i = 0; i < result.length; i++) {
                    let packageSql = `SELECT pc.*, p.name as packageName, p.baseAmount as packageBaseAmount FROM packagecoupons pc INNER JOIN package p ON p.id = pc.packageId WHERE pc.couponId = ` + result[i].id;
                    let packageResult = await header.query(packageSql);
                    result[i].packages = packageResult;
                }
                let successResult = new ResultSuccess(200, true, 'Get Coupons Successfully', result, countResult[0].totalCount, authorizationResult.token);
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
        let errorResult = new ResultError(500, true, 'coupons.getCoupons() Exception', error, '');
        next(errorResult);
    }
};

const insertUpdateCoupon = async (req: Request, res: Response, next: NextFunction) => {
    await header.beginTransaction();
    try {
        logging.info(NAMESPACE, 'Inserting Coupons');
        let requiredFields = ['name', 'code', 'type', 'value'];
        //, 'maxUsage', 'userUsage', 'validFrom', 'validTo', 'maxDiscountAmount'
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let currentUser = authorizationResult.currentUser;
                let userId = currentUser.id;
                let checkSql = `SELECT * FROM coupons WHERE code = '` + req.body.code + `'`;
                if (req.body.id) {
                    checkSql += ' AND id != ' + req.body.id;
                }
                let checkResult = await header.query(checkSql);
                if (checkResult && checkResult.length > 0) {
                    let errorResult = new ResultError(203, true, "", new Error("Code Already Exist"), '');
                    next(errorResult);
                } else {
                    if (req.body.id) {
                        let sql = `UPDATE coupons SET name = '` + req.body.name + `', code='` + req.body.code + `', type='` + req.body.type + `', value=` + req.body.value + `, maxUsage=` + (req.body.maxUsage ? req.body.maxUsage : null) + `
                        , userUsage=`+ (req.body.userUsage ? req.body.userUsage : null) + `, validFrom = ?, validTo = ?, maxDiscountAmount = ` + (req.body.maxDiscountAmount ? req.body.maxDiscountAmount : null) + `, description='` + req.body.description + `'
                        , termsCondition = '`+ req.body.termsCondition + `', modifiedDate = CURRENT_TIMESTAMP(), modifiedBy = ` + userId + ` where id = ` + req.body.id + ``;
                        let result = await header.query(sql, [(req.body.validFrom ? new Date(req.body.validFrom) : null), (req.body.validTo ? new Date(req.body.validTo) : null)]);
                        if (result && result.affectedRows > 0) {
                            let packageSql = `SELECT * FROM packagecoupons WHERE couponId = ` + req.body.id;
                            let packageResult = await header.query(packageSql);
                            let removeIds: number[] = [];
                            if (packageResult && packageResult.length > 0) {
                                removeIds = packageResult.map((c: any) => c.id);
                            }
                            if (req.body.packages && req.body.packages.length > 0) {
                                for (let i = 0; i < req.body.packages.length; i++) {
                                    removeIds.splice(removeIds.findIndex(c => c == req.body.packages[i].id), 1)
                                    if (!req.body.packages[i].id) {
                                        let packageCouponSql = `INSERT INTO packagecoupons(packageId, couponId, isActive, isDelete, createdBy, modifiedBy) VALUES(` + req.body.packages[i].packageId + `,` + req.body.id + `, 1, 0, ` + userId + `,` + userId + `)`;
                                        let packageCouponResult = await header.query(packageCouponSql);
                                        if (packageCouponResult && packageCouponResult.insertId) {

                                        } else {
                                            await header.rollback();
                                            let errorResult = new ResultError(400, true, "coupons.insertUpdateCoupon() Error", new Error('Error While Updating Data'), '');
                                            next(errorResult);
                                            return errorResult
                                        }
                                    }
                                }

                                if (removeIds && removeIds.length > 0) {
                                    let deleteSql = `DELETE FROM packagecoupons WHERE id IN(` + removeIds.toString() + `)`;
                                    let deleteResult = await header.query(deleteSql);
                                    if (deleteResult && deleteResult.affectedRows >= 0) {

                                    } else {
                                        await header.rollback();
                                        let errorResult = new ResultError(400, true, "Error While Delete package coupons", new Error('Error While Delete package coupons'), '');
                                        next(errorResult);
                                    }
                                }
                            } else {
                                if (removeIds && removeIds.length > 0) {
                                    let deleteSql = `DELETE FROM packagecoupons WHERE id IN(` + removeIds.toString() + `)`;
                                    let deleteResult = await header.query(deleteSql);
                                    if (deleteResult && deleteResult.affectedRows >= 0) {

                                    } else {
                                        await header.rollback();
                                        let errorResult = new ResultError(400, true, "Error While Delete package coupons", new Error('Error While Delete package coupons'), '');
                                        next(errorResult);
                                    }
                                }
                            }
                            await header.commit();
                            let successResult = new ResultSuccess(200, true, 'Update Coupon', result, 1, authorizationResult.token);
                            return res.status(200).send(successResult);
                        }
                        else {
                            await header.rollback();
                            let errorResult = new ResultError(400, true, "coupons.insertUpdateCoupon() Error", new Error('Error While Updating Data'), '');
                            next(errorResult);
                        }
                    } else {
                        let sql = `INSERT INTO coupons(name, code, type, value, maxUsage, userUsage, validFrom, validTo, maxDiscountAmount, description, termsCondition, isActive, isDelete, createdBy, modifiedBy) 
                        VALUES('` + req.body.name + `', '` + req.body.code + `', '` + req.body.type + `', ` + req.body.value + `, ` + (req.body.maxUsage ? req.body.maxUsage : null) + `
                        , ` + (req.body.userUsage ? req.body.userUsage : null) + `, ?, ?, ` + (req.body.maxDiscountAmount ? req.body.maxDiscountAmount : null) + ` , '` + req.body.description + `'
                        , '` + req.body.termsCondition + `', 1, 0, ` + userId + `,` + userId + `);`;
                        let result = await header.query(sql, [(req.body.validFrom ? new Date(req.body.validFrom) : null), (req.body.validTo ? new Date(req.body.validTo) : null)]);
                        if (result && result.affectedRows > 0) {
                            let couponId = result.insertId;
                            if (req.body.packages && req.body.packages.length > 0) {
                                for (let i = 0; i < req.body.packages.length; i++) {
                                    let packageCouponSql = `INSERT INTO packagecoupons(packageId, couponId, isActive, isDelete, createdBy, modifiedBy) VALUES(` + req.body.packages[i].packageId + `,` + couponId + `, 1, 0, ` + userId + `,` + userId + `)`;
                                    let packageCouponResult = await header.query(packageCouponSql);
                                    if (packageCouponResult && packageCouponResult.insertId) {

                                    } else {
                                        await header.rollback();
                                        let errorResult = new ResultError(400, true, "coupons.insertUpdateCoupon() Error", new Error('Error While Updating Data'), '');
                                        next(errorResult);
                                        return errorResult
                                    }
                                }
                            }
                            await header.commit();
                            let successResult = new ResultSuccess(200, true, 'Insert Coupon', result, 1, authorizationResult.token);
                            return res.status(200).send(successResult);
                        }
                        else {
                            await header.rollback();
                            let errorResult = new ResultError(400, true, "coupons.insertUpdateCoupon() Error", new Error('Error While Inserting Data'), '');
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
        let errorResult = new ResultError(500, true, 'coupons.insertUpdateCoupon() Exception', error, '');
        next(errorResult);
    }
};

const activeInactiveCoupon = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Active Inactive Coupon');
        let requiredFields = ['id'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let sql = `UPDATE coupons set isActive = !isActive WHERE id = ` + req.body.id + ``;
                let result = await header.query(sql);
                if (result && result.affectedRows > 0) {
                    let successResult = new ResultSuccess(200, true, 'Change Coupon Status', result, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                }
                else {
                    let errorResult = new ResultError(400, true, "coupons.activeInactiveCoupon() Error", new Error('Error While Change Coupon Status'), '');
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
        let errorResult = new ResultError(500, true, 'coupons.activeInactiveCoupon() Exception', error, '');
        next(errorResult);
    }
};

export default { getCoupons, insertUpdateCoupon, activeInactiveCoupon }