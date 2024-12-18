import { NextFunction, Request, Response, query } from 'express';
import logging from "../../config/logging";
import header from "../../middleware/apiHeader";
import { ResultSuccess } from '../../classes/response/resultsuccess';
import { ResultError } from '../../classes/response/resulterror';

const NAMESPACE = 'Region';

const getCountries = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Countries');
        let requiredFields = [''];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let countSql = `SELECT COUNT(id) as totalRecords FROM countries`;
                let countrySql = `SELECT * FROM countries`;
                if (req.body.searchString) {
                    if (!countSql.includes(` WHERE `)) {
                        countSql += ` WHERE `;
                    } else {
                        countSql += ` AND `;
                    }
                    countSql += ` LOWER(name) LIKE '%` + req.body.searchString.toLowerCase() + `%' `;

                    if (!countrySql.includes(` WHERE `)) {
                        countrySql += ` WHERE `;
                    } else {
                        countrySql += ` AND `;
                    }
                    countrySql += ` LOWER(name) LIKE '%` + req.body.searchString.toLowerCase() + `%' `;
                }
                if (req.body.fetchRecord) {
                    countrySql += ` LIMIT ` + req.body.fetchRecord + ` OFFSET ` + req.body.startIndex;
                }
                let countryResult = await header.query(countrySql);
                let countResult = await header.query(countSql);
                if (countryResult && countryResult.length > 0) {
                    let totalCount = countResult[0].totalRecords;
                    let successResult = new ResultSuccess(200, true, 'Get Countries Successfully', countryResult, totalCount, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let successResult = new ResultSuccess(200, true, 'Countries Not Available', [], 0, authorizationResult.token);
                    return res.status(200).send(successResult);
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
        let errorResult = new ResultError(500, true, 'region.getCountries() Exception', error, '');
        next(errorResult);
    }
}

const insertCountry = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Insert Countries');
        let requiredFields = ['name', 'isoCode', 'isoCode3'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let sql = `INSERT INTO countries(name, isoCode, isoCode3, dialCode) VALUES('` + req.body.name + `','` + req.body.isoCode + `','` + req.body.isoCode3 + `','` + req.body.dialCode + `')`;
                let result = await header.query(sql);
                if (result && result.insertId > 0) {
                    let successResult = new ResultSuccess(200, true, 'Insert Country Successfully', result, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "region.insertCountry() Error", new Error('Error While Inserting Country'), '');
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
        let errorResult = new ResultError(500, true, 'region.insertCountry() Exception', error, '');
        next(errorResult);
    }
}

const updateCountry = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Update Countries');
        let requiredFields = ['id', 'name', 'isoCode', 'isoCode3'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let sql = `UPDATE countries SET name = '` + req.body.name + `', isoCode = '` + req.body.isoCode + `', isoCode3 = '` + req.body.isoCode3 + `', dialCode = '` + req.body.dialCode + `'
                 WHERE id = `+ req.body.id;
                let result = await header.query(sql);
                if (result && result.affectedRows > 0) {
                    let successResult = new ResultSuccess(200, true, 'Update Country Successfully', result, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "region.updateCountry() Error", new Error('Error While Updating Country'), '');
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
        let errorResult = new ResultError(500, true, 'region.updateCountry() Exception', error, '');
        next(errorResult);
    }
}

const activeInactiveCountry = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Update Countries');
        let requiredFields = ['id'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let sql = `UPDATE countries SET isActive = !isActive WHERE id = ` + req.body.id;
                let result = await header.query(sql);
                if (result && result.affectedRows > 0) {
                    let successResult = new ResultSuccess(200, true, 'Update Country Status Successfully', result, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "region.activeInactiveCountry() Error", new Error('Error While Updating Country Status'), '');
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
        let errorResult = new ResultError(500, true, 'region.activeInactiveCountry() Exception', error, '');
        next(errorResult);
    }
}

const getStates = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting States');
        let requiredFields = [''];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let countSql = `SELECT COUNT(s.id) as totalRecords FROM state s INNER JOIN countries c ON c.id = s.countryId`;
                let stateSql = `SELECT s.*, c.name as countryName FROM state s INNER JOIN countries c ON c.id = s.countryId`;
                if (req.body.countryId) {
                    if (!countSql.includes(` WHERE `)) {
                        countSql += ` WHERE `;
                    } else {
                        countSql += ` AND `;
                    }
                    countSql += ` s.countryId =` + req.body.countryId;

                    if (!stateSql.includes(` WHERE `)) {
                        stateSql += ` WHERE `;
                    } else {
                        stateSql += ` AND `;
                    }
                    stateSql += ` s.countryId =` + req.body.countryId;
                }
                if (req.body.searchString) {
                    if (!countSql.includes(` WHERE `)) {
                        countSql += ` WHERE `;
                    } else {
                        countSql += ` AND `;
                    }
                    countSql += ` LOWER(s.name) LIKE '%` + req.body.searchString.toLowerCase() + `%' `;

                    if (!stateSql.includes(` WHERE `)) {
                        stateSql += ` WHERE `;
                    } else {
                        stateSql += ` AND `;
                    }
                    stateSql += ` LOWER(s.name) LIKE '%` + req.body.searchString.toLowerCase() + `%' `;
                }
                if (req.body.fetchRecord) {
                    stateSql += ` LIMIT ` + req.body.fetchRecord + ` OFFSET ` + req.body.startIndex;
                }
                let stateResult = await header.query(stateSql);
                let countResult = await header.query(countSql);
                if (stateResult && stateResult.length > 0) {
                    let totalCount = countResult[0].totalRecords;
                    let successResult = new ResultSuccess(200, true, 'Get States Successfully', stateResult, totalCount, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let successResult = new ResultSuccess(200, true, 'States Not Available', [], 0, authorizationResult.token);
                    return res.status(200).send(successResult);
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
        let errorResult = new ResultError(500, true, 'region.getStates() Exception', error, '');
        next(errorResult);
    }
}

const insertState = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Insert State');
        let requiredFields = ['name', 'countryId'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let sql = `INSERT INTO state(name, countryId, code) VALUES('` + req.body.name + `',` + req.body.countryId + `,` + (req.body.code ? "'" + req.body.code + "'" : null) + `)`;
                let result = await header.query(sql);
                if (result && result.insertId > 0) {
                    let successResult = new ResultSuccess(200, true, 'Insert State Successfully', result, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "region.insertState() Error", new Error('Error While Inserting State'), '');
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
        let errorResult = new ResultError(500, true, 'region.insertState() Exception', error, '');
        next(errorResult);
    }
}

const updateState = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Update State');
        let requiredFields = ['id', 'name', 'countryId'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let sql = `UPDATE state SET name = '` + req.body.name + `', code = ` + (req.body.code ? `'` + req.body.code + `'` : null) + `, countryId = ` + req.body.countryId + ` WHERE id = ` + req.body.id;
                let result = await header.query(sql);
                if (result && result.affectedRows > 0) {
                    let successResult = new ResultSuccess(200, true, 'Update State Successfully', result, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "region.updateState() Error", new Error('Error While Updating State'), '');
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
        let errorResult = new ResultError(500, true, 'region.updateState() Exception', error, '');
        next(errorResult);
    }
}

const activeInactiveState = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Update State');
        let requiredFields = ['id'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let sql = `UPDATE state SET isActive = !isActive WHERE id = ` + req.body.id;
                let result = await header.query(sql);
                if (result && result.affectedRows > 0) {
                    let successResult = new ResultSuccess(200, true, 'Update State Status Successfully', result, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "region.activeInactiveState() Error", new Error('Error While Updating State Status'), '');
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
        let errorResult = new ResultError(500, true, 'region.activeInactiveState() Exception', error, '');
        next(errorResult);
    }
}

const getDistricts = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Districts');
        let requiredFields = [''];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let countSql = `SELECT COUNT(d.id) as totalRecords FROM districts d INNER JOIN state s ON s.id = d.stateId INNER JOIN countries ct ON ct.id = s.countryId`;
                let districtSql = `SELECT d.*, ct.id as countryId, s.name as stateName, ct.name as countryName  FROM districts d INNER JOIN state s ON s.id = d.stateId INNER JOIN countries ct ON ct.id = s.countryId`;
                if (req.body.stateId) {
                    if (!countSql.includes(` WHERE `)) {
                        countSql += ` WHERE `;
                    } else {
                        countSql += ` AND `;
                    }
                    countSql += ` d.stateId =` + req.body.stateId;

                    if (!districtSql.includes(` WHERE `)) {
                        districtSql += ` WHERE `;
                    } else {
                        districtSql += ` AND `;
                    }
                    districtSql += ` d.stateId =` + req.body.stateId;
                }
                if (req.body.countryId) {
                    if (!countSql.includes(` WHERE `)) {
                        countSql += ` WHERE `;
                    } else {
                        countSql += ` AND `;
                    }
                    countSql += ` ct.id=` + req.body.countryId;

                    if (!districtSql.includes(` WHERE `)) {
                        districtSql += ` WHERE `;
                    } else {
                        districtSql += ` AND `;
                    }
                    districtSql += ` ct.id =` + req.body.countryId;
                }
                if (req.body.searchString) {
                    if (!countSql.includes(` WHERE `)) {
                        countSql += ` WHERE `;
                    } else {
                        countSql += ` AND `;
                    }
                    countSql += ` LOWER(d.name) LIKE '%` + req.body.searchString.toLowerCase() + `%' `;

                    if (!districtSql.includes(` WHERE `)) {
                        districtSql += ` WHERE `;
                    } else {
                        districtSql += ` AND `;
                    }
                    districtSql += ` LOWER(d.name) LIKE '%` + req.body.searchString.toLowerCase() + `%' `;
                }
                if (req.body.fetchRecord) {
                    districtSql += ` LIMIT ` + req.body.fetchRecord + ` OFFSET ` + req.body.startIndex;
                }
                let districtResult = await header.query(districtSql);
                let countResult = await header.query(countSql);
                if (districtResult && districtResult.length > 0) {
                    let totalCount = countResult[0].totalRecords;
                    let successResult = new ResultSuccess(200, true, 'Get District Successfully', districtResult, totalCount, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let successResult = new ResultSuccess(200, true, 'District Not Available', [], 0, authorizationResult.token);
                    return res.status(200).send(successResult);
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
        let errorResult = new ResultError(500, true, 'region.getDistricts() Exception', error, '');
        next(errorResult);
    }
}

const insertDistrict = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Insert District');
        let requiredFields = ['name', 'stateId'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let sql = `INSERT INTO districts(name, stateId) VALUES('` + req.body.name + `',` + req.body.stateId + `)`;
                let result = await header.query(sql);
                if (result && result.insertId > 0) {
                    let successResult = new ResultSuccess(200, true, 'Insert District Successfully', result, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "region.insertDistrict() Error", new Error('Error While Inserting District'), '');
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
        let errorResult = new ResultError(500, true, 'region.insertDistrict() Exception', error, '');
        next(errorResult);
    }
}

const updateDistrict = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Update District');
        let requiredFields = ['id', 'name', 'stateId'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let sql = `UPDATE districts SET name = '` + req.body.name + `', stateId = ` + req.body.stateId + ` WHERE id = ` + req.body.id;
                let result = await header.query(sql);
                if (result && result.affectedRows > 0) {
                    let successResult = new ResultSuccess(200, true, 'Update District Successfully', result, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "region.updateDistrict() Error", new Error('Error While Updating District'), '');
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
        let errorResult = new ResultError(500, true, 'region.updateDistrict() Exception', error, '');
        next(errorResult);
    }
}

const activeInactiveDistrict = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Update District');
        let requiredFields = ['id'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let sql = `UPDATE districts SET isActive = !isActive WHERE id = ` + req.body.id;
                let result = await header.query(sql);
                if (result && result.affectedRows > 0) {
                    let successResult = new ResultSuccess(200, true, 'Update District Status Successfully', result, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "region.activeInactiveDistrict() Error", new Error('Error While Updating District Status'), '');
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
        let errorResult = new ResultError(500, true, 'region.activeInactiveDistrict() Exception', error, '');
        next(errorResult);
    }
}

const getCities = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Cities');
        let requiredFields = [''];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let countSql = `SELECT COUNT(c.id) as totalRecords FROM cities c
                INNER JOIN districts d ON d.id = c.districtId 
                INNER JOIN state s ON s.id = d.stateId 
                INNER JOIN countries ct ON ct.id = s.countryId`;
                let citySql = `SELECT c.*, ct.id as countryId, s.id as stateId, d.name as districtName, s.name as stateName, ct.name as countryName 
                FROM cities c 
                INNER JOIN districts d ON d.id = c.districtId 
                INNER JOIN state s ON s.id = d.stateId 
                INNER JOIN countries ct ON ct.id = s.countryId`;
                if (req.body.districtId) {
                    if (!countSql.includes(` WHERE `)) {
                        countSql += ` WHERE `;
                    } else {
                        countSql += ` AND `;
                    }
                    countSql += ` c.districtId =` + req.body.districtId;

                    if (!citySql.includes(` WHERE `)) {
                        citySql += ` WHERE `;
                    } else {
                        citySql += ` AND `;
                    }
                    citySql += ` c.districtId =` + req.body.districtId;
                }
                if (req.body.stateId) {
                    if (!countSql.includes(` WHERE `)) {
                        countSql += ` WHERE `;
                    } else {
                        countSql += ` AND `;
                    }
                    countSql += ` s.id=` + req.body.stateId;

                    if (!citySql.includes(` WHERE `)) {
                        citySql += ` WHERE `;
                    } else {
                        citySql += ` AND `;
                    }
                    citySql += ` s.id =` + req.body.stateId;
                }
                if (req.body.countryId) {
                    if (!countSql.includes(` WHERE `)) {
                        countSql += ` WHERE `;
                    } else {
                        countSql += ` AND `;
                    }
                    countSql += ` ct.id=` + req.body.countryId;

                    if (!citySql.includes(` WHERE `)) {
                        citySql += ` WHERE `;
                    } else {
                        citySql += ` AND `;
                    }
                    citySql += ` ct.id =` + req.body.countryId;
                }
                if (req.body.searchString) {
                    if (!countSql.includes(` WHERE `)) {
                        countSql += ` WHERE `;
                    } else {
                        countSql += ` AND `;
                    }
                    countSql += ` LOWER(c.name) LIKE '%` + req.body.searchString.toLowerCase() + `%' `;

                    if (!citySql.includes(` WHERE `)) {
                        citySql += ` WHERE `;
                    } else {
                        citySql += ` AND `;
                    }
                    citySql += ` LOWER(c.name) LIKE '%` + req.body.searchString.toLowerCase() + `%' `;
                }
                if (req.body.fetchRecord) {
                    citySql += ` LIMIT ` + req.body.fetchRecord + ` OFFSET ` + req.body.startIndex;
                }
                let cityResult = await header.query(citySql);
                let countResult = await header.query(countSql);
                if (cityResult && cityResult.length > 0) {
                    let totalCount = countResult[0].totalRecords;
                    let successResult = new ResultSuccess(200, true, 'Get City Successfully', cityResult, totalCount, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let successResult = new ResultSuccess(200, true, 'City Not Available', [], 0, authorizationResult.token);
                    return res.status(200).send(successResult);
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
        let errorResult = new ResultError(500, true, 'region.getCities() Exception', error, '');
        next(errorResult);
    }
}

const insertCity = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Insert City');
        let requiredFields = ['name', 'districtId', 'pincode'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let sql = `INSERT INTO cities(name, districtId,pincode) VALUES('` + req.body.name + `',` + req.body.districtId + `, '` + req.body.pincode + `')`;
                let result = await header.query(sql);
                if (result && result.insertId > 0) {
                    let successResult = new ResultSuccess(200, true, 'Insert City Successfully', result, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "region.insertCity() Error", new Error('Error While Inserting City'), '');
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
        let errorResult = new ResultError(500, true, 'region.insertCity() Exception', error, '');
        next(errorResult);
    }
}

const updateCity = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Update City');
        let requiredFields = ['id', 'name', 'pincode', 'districtId'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let sql = `UPDATE cities SET name = '` + req.body.name + `', pincode = '` + req.body.pincode + `', districtId = ` + req.body.districtId + ` WHERE id = ` + req.body.id;
                let result = await header.query(sql);
                if (result && result.affectedRows > 0) {
                    let successResult = new ResultSuccess(200, true, 'Update City Successfully', result, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "region.updateCity() Error", new Error('Error While Updating City'), '');
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
        let errorResult = new ResultError(500, true, 'region.updateCity() Exception', error, '');
        next(errorResult);
    }
}

const activeInactiveCity = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Update City');
        let requiredFields = ['id'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let sql = `UPDATE cities SET isActive = !isActive WHERE id = ` + req.body.id;
                let result = await header.query(sql);
                if (result && result.affectedRows > 0) {
                    let successResult = new ResultSuccess(200, true, 'Update City Status Successfully', result, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "region.activeInactiveCity() Error", new Error('Error While Updating City Status'), '');
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
        let errorResult = new ResultError(500, true, 'region.activeInactiveCity() Exception', error, '');
        next(errorResult);
    }
}

const getAllRegionData = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting All Region Data');
        let requiredFields = [''];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let citySql = `SELECT ct.id as countryId, ct.name as countryName ,ct.isoCode, ct.isoCode3, ct.dialCode, s.id as stateId, s.name as stateName, c.districtId, d.name as districtName, 
                c.id as cityId, c.name as cityName, c.pincode
                FROM cities c 
                INNER JOIN districts d ON d.id = c.districtId 
                INNER JOIN state s ON s.id = d.stateId 
                INNER JOIN countries ct ON ct.id = s.countryId`;
                let cityResult = await header.query(citySql);
                if (cityResult && cityResult.length > 0) {
                    let successResult = new ResultSuccess(200, true, 'Get Region Data Successfully', cityResult, cityResult.length, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let successResult = new ResultSuccess(200, true, 'Region Data Not Available', [], 0, authorizationResult.token);
                    return res.status(200).send(successResult);
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
        let errorResult = new ResultError(500, true, 'region.getAllRegionData() Exception', error, '');
        next(errorResult);
    }
}

const updateRegionData = async (req: Request, res: Response, next: NextFunction) => {
    await header.beginTransaction();
    try {
        logging.info(NAMESPACE, 'Update All Region Data');
        let requiredFields = [''];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let result;
                for (let i = 0; i < req.body.data.length; i++) {
                    if (!req.body.data[i].pincode) {
                        req.body.data[i].pincode = "00000";
                    }
                    if (i % 5000 == 0) {
                        console.log(i);
                    }
                    if (parseInt(req.body.data[i].countryId)) {
                        let countryId = req.body.data[i].countryId;
                        //update Country
                        if (req.body.data[i].countryName) {
                            let updateCountrySql = `UPDATE countries SET name = ?, isoCode = ` + (req.body.data[i].isoCode ? ("'" + req.body.data[i].isoCode + "'") : null) + `
                            , isoCode3 = `+ (req.body.data[i].isoCode3 ? ("'" + req.body.data[i].isoCode3 + "'") : null) + `, dialCode = ` + (req.body.data[i].dialCode ? ("'" + req.body.data[i].dialCode + "'") : null) + `
                             WHERE id = ` + parseInt(req.body.data[i].countryId);
                            result = await header.query(updateCountrySql, [req.body.data[i].countryName]);
                            if (result && result.affectedRows >= 0) {

                            } else {
                                await header.rollback();
                                let errorResult = new ResultError(400, true, "Error While Updating Country", new Error("Error While Updating Country"), '');
                                next(errorResult);
                            }
                        }
                        if (parseInt(req.body.data[i].stateId)) {
                            let stateId = req.body.data[i].stateId;
                            //update State
                            if (req.body.data[i].stateName) {
                                let updateStateSql = `UPDATE state SET name = ?, countryId = ` + countryId + ` WHERE id = ` + parseInt(stateId);
                                result = await header.query(updateStateSql, [req.body.data[i].stateName]);
                                if (result && result.affectedRows >= 0) {

                                } else {
                                    await header.rollback();
                                    let errorResult = new ResultError(400, true, "Error While Updating State", new Error("Error While Updating State"), '');
                                    next(errorResult);
                                }
                            }
                            if (parseInt(req.body.data[i].districtId)) {
                                //update District
                                let districtId = req.body.data[i].districtId;
                                if (req.body.data[i].districtName) {
                                    let updateDistrictSql = `UPDATE districts SET name = ?, stateId = ` + stateId + ` WHERE id = ` + parseInt(districtId);
                                    result = await header.query(updateDistrictSql, [req.body.data[i].districtName]);
                                    if (result && result.affectedRows >= 0) {

                                    } else {
                                        await header.rollback();
                                        let errorResult = new ResultError(400, true, "Error While Updating District", new Error("Error While Updating District"), '');
                                        next(errorResult);
                                    }
                                }
                                if (parseInt(req.body.data[i].cityId)) {
                                    //update City
                                    let cityId = req.body.data[i].cityId;
                                    if (req.body.data[i].cityName && req.body.data[i].pincode) {
                                        let updateCitySql = `UPDATE cities SET name = ?, districtId = ` + districtId + `, pincode = '` + req.body.data[i].pincode + `' WHERE id = ` + parseInt(cityId);
                                        result = await header.query(updateCitySql, [req.body.data[i].cityName]);
                                        if (result && result.affectedRows >= 0) {

                                        } else {
                                            await header.rollback();
                                            let errorResult = new ResultError(400, true, "Error While Updating City", new Error("Error While Updating City"), '');
                                            next(errorResult);
                                        }
                                    }
                                } else {
                                    //insert City
                                    let cityId;
                                    if (req.body.data[i].cityName && req.body.data[i].pincode) {
                                        let insertCitySql = `INSERT INTO cities(name, districtId, pincode) VALUES(?, ` + districtId + `,'` + req.body.data[i].pincode + `')`;
                                        result = await header.query(insertCitySql, [req.body.data[i].cityName]);
                                        if (result && result.insertId >= 0) {
                                            cityId = result.insertId;
                                        } else {
                                            await header.rollback();
                                            let errorResult = new ResultError(400, true, "Error While Inserting City", new Error("Error While Inserting City"), '');
                                            next(errorResult);
                                        }
                                    }
                                }
                            } else {
                                //insert District
                                let districtId;
                                if (parseInt(req.body.data[i].districtName)) {
                                    let insertDistrictSql = `INSERT INTO districts(name, stateId) VALUES(?, ` + stateId + `)`;
                                    result = await header.query(insertDistrictSql, [req.body.data[i].districtName]);
                                    if (result && result.insertId > 0) {
                                        districtId = result.insertId;
                                    } else {
                                        await header.rollback();
                                        let errorResult = new ResultError(400, true, "Error While Updating District", new Error("Error While Updating District"), '');
                                        next(errorResult);
                                    }
                                }
                                if (parseInt(req.body.data[i].cityId)) {
                                    //update City
                                    let cityId = req.body.data[i].cityId;
                                    if (req.body.data[i].cityName && req.body.data[i].pincode) {
                                        let updateCitySql = `UPDATE cities SET name = ?, districtId = ` + districtId + `, pincode = '` + req.body.data[i].pincode + `' WHERE id = ` + parseInt(cityId);
                                        result = await header.query(updateCitySql, [req.body.data[i].cityName]);
                                        if (result && result.affectedRows >= 0) {

                                        } else {
                                            await header.rollback();
                                            let errorResult = new ResultError(400, true, "Error While Updating City", new Error("Error While Updating City"), '');
                                            next(errorResult);
                                        }
                                    }
                                } else {
                                    //insert City
                                    let cityId;
                                    if (req.body.data[i].cityName && req.body.data[i].pincode) {
                                        let insertCitySql = `INSERT INTO cities(name, districtId, pincode) VALUES(?, ` + districtId + `,'` + req.body.data[i].pincode + `')`;
                                        result = await header.query(insertCitySql, [req.body.data[i].cityName]);
                                        if (result && result.insertId >= 0) {
                                            cityId = result.insertId;
                                        } else {
                                            await header.rollback();
                                            let errorResult = new ResultError(400, true, "Error While Inserting City", new Error("Error While Inserting City"), '');
                                            next(errorResult);
                                        }
                                    }
                                }
                            }
                        } else {
                            //insert State
                            let stateId;
                            if (req.body.data[i].stateName) {
                                let insertStateSql = `INSERT INTO state(name,countryId) VALUS(?, ` + countryId + `)`;
                                result = await header.query(insertStateSql, [req.body.data[i].stateName]);
                                if (result && result.insertId > 0) {
                                    stateId = result.insertId;
                                } else {
                                    await header.rollback();
                                    let errorResult = new ResultError(400, true, "Error While Insert State", new Error("Error While Insert State"), '');
                                    next(errorResult);
                                }
                            }
                            if (parseInt(req.body.data[i].districtId)) {
                                //update District
                                let districtId = req.body.data[i].districtId;
                                if (req.body.data[i].districtName) {
                                    let updateDistrictSql = `UPDATE districts SET name = ?, stateId = ` + stateId + ` WHERE id = ` + parseInt(districtId);
                                    result = await header.query(updateDistrictSql, [req.body.data[i].districtName]);
                                    if (result && result.affectedRows >= 0) {

                                    } else {
                                        await header.rollback();
                                        let errorResult = new ResultError(400, true, "Error While Updating District", new Error("Error While Updating District"), '');
                                        next(errorResult);
                                    }
                                }
                                if (parseInt(req.body.data[i].cityId)) {
                                    //update City
                                    let cityId = req.body.data[i].cityId;
                                    if (req.body.data[i].cityName && req.body.data[i].pincode) {
                                        let updateCitySql = `UPDATE cities SET name = ?, districtId = ` + districtId + `, pincode = '` + req.body.data[i].pincode + `' WHERE id = ` + parseInt(cityId);
                                        result = await header.query(updateCitySql, [req.body.data[i].cityName]);
                                        if (result && result.affectedRows >= 0) {

                                        } else {
                                            await header.rollback();
                                            let errorResult = new ResultError(400, true, "Error While Updating City", new Error("Error While Updating City"), '');
                                            next(errorResult);
                                        }
                                    }
                                } else {
                                    //insert City
                                    let cityId;
                                    if (req.body.data[i].cityName && req.body.data[i].pincode) {
                                        let insertCitySql = `INSERT INTO cities(name, districtId, pincode) VALUES(?, ` + districtId + `,'` + req.body.data[i].pincode + `')`;
                                        result = await header.query(insertCitySql, [req.body.data[i].cityName]);
                                        if (result && result.insertId >= 0) {
                                            cityId = result.insertId;
                                        } else {
                                            await header.rollback();
                                            let errorResult = new ResultError(400, true, "Error While Inserting City", new Error("Error While Inserting City"), '');
                                            next(errorResult);
                                        }
                                    }
                                }
                            } else {
                                //insert District
                                let districtId;
                                if (req.body.data[i].districtName) {
                                    let insertDistrictSql = `INSERT INTO districts(name, stateId) VALUES(?, ` + stateId + `)`;
                                    result = await header.query(insertDistrictSql, [req.body.data[i].districtName]);
                                    if (result && result.insertId > 0) {
                                        districtId = result.insertId;
                                    } else {
                                        await header.rollback();
                                        let errorResult = new ResultError(400, true, "Error While Updating District", new Error("Error While Updating District"), '');
                                        next(errorResult);
                                    }
                                }
                                if (parseInt(req.body.data[i].cityId)) {
                                    //update City
                                    let cityId = req.body.data[i].cityId;
                                    if (req.body.data[i].cityName && req.body.data[i].pincode) {
                                        let updateCitySql = `UPDATE cities SET name = ?, districtId = ` + districtId + `, pincode = '` + req.body.data[i].pincode + `' WHERE id = ` + parseInt(cityId);
                                        result = await header.query(updateCitySql, [req.body.data[i].cityName]);
                                        if (result && result.affectedRows >= 0) {

                                        } else {
                                            await header.rollback();
                                            let errorResult = new ResultError(400, true, "Error While Updating City", new Error("Error While Updating City"), '');
                                            next(errorResult);
                                        }
                                    }
                                } else {
                                    //insert City
                                    let cityId;
                                    if (req.body.data[i].cityName && req.body.data[i].pincode) {
                                        let insertCitySql = `INSERT INTO cities(name, districtId, pincode) VALUES(?, ` + districtId + `,'` + req.body.data[i].pincode + `')`;
                                        result = await header.query(insertCitySql, [req.body.data[i].cityName]);
                                        if (result && result.insertId >= 0) {
                                            cityId = result.insertId;
                                        } else {
                                            await header.rollback();
                                            let errorResult = new ResultError(400, true, "Error While Inserting City", new Error("Error While Inserting City"), '');
                                            next(errorResult);
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        //insert Country
                        let countryId;
                        if (req.body.data[i].countryName) {
                            let insertCountrySql = `INSERT INTO countries(name, isoCode, isoCode3, dialCode) VALUES(?, ` + (req.body.data[i].isoCode ? ("'" + req.body.data[i].isoCode + "'") : null) + `
                            , `+ (req.body.data[i].isoCode3 ? ("'" + req.body.data[i].isoCode3 + "'") : null) + `, ` + (req.body.data[i].dialCode ? ("'" + req.body.data[i].dialCode + "'") : null) + `)`;
                            result = await header.query(insertCountrySql, [req.body.data[i].countryName]);
                            if (result && result.insertId > 0) {
                                countryId = result.insertId;
                            } else {
                                await header.rollback();
                                let errorResult = new ResultError(400, true, "Error While Updating Country", new Error("Error While Updating Country"), '');
                                next(errorResult);
                            }
                        }
                        if (parseInt(req.body.data[i].stateId)) {
                            let stateId = req.body.data[i].stateId;
                            //update State
                            if (req.body.data[i].stateName) {
                                let updateStateSql = `UPDATE state SET name = ?, countryId = ` + countryId + ` WHERE id = ` + parseInt(stateId);
                                result = await header.query(updateStateSql, [req.body.data[i].stateName]);
                                if (result && result.affectedRows >= 0) {

                                } else {
                                    await header.rollback();
                                    let errorResult = new ResultError(400, true, "Error While Updating State", new Error("Error While Updating State"), '');
                                    next(errorResult);
                                }
                            }
                            if (parseInt(req.body.data[i].districtId)) {
                                //update District
                                let districtId = req.body.data[i].districtId;
                                if (req.body.data[i].districtName) {
                                    let updateDistrictSql = `UPDATE districts SET name = ?, stateId = ` + stateId + ` WHERE id = ` + parseInt(districtId);
                                    result = await header.query(updateDistrictSql, [req.body.data[i].districtName]);
                                    if (result && result.affectedRows >= 0) {

                                    } else {
                                        await header.rollback();
                                        let errorResult = new ResultError(400, true, "Error While Updating District", new Error("Error While Updating District"), '');
                                        next(errorResult);
                                    }
                                }
                                if (parseInt(req.body.data[i].cityId)) {
                                    //update City
                                    let cityId = req.body.data[i].cityId;
                                    if (req.body.data[i].cityName && req.body.data[i].pincode) {
                                        let updateCitySql = `UPDATE cities SET name = ?, districtId = ` + districtId + `, pincode = '` + req.body.data[i].pincode + `' WHERE id = ` + parseInt(cityId);
                                        result = await header.query(updateCitySql, [req.body.data[i].cityName]);
                                        if (result && result.affectedRows >= 0) {

                                        } else {
                                            await header.rollback();
                                            let errorResult = new ResultError(400, true, "Error While Updating City", new Error("Error While Updating City"), '');
                                            next(errorResult);
                                        }
                                    }
                                } else {
                                    //insert City
                                    let cityId;
                                    if (req.body.data[i].cityName && req.body.data[i].pincode) {
                                        let insertCitySql = `INSERT INTO cities(name, districtId, pincode) VALUES(, ` + districtId + `,'` + req.body.data[i].pincode + `')`;
                                        result = await header.query(insertCitySql, [req.body.data[i].cityName]);
                                        if (result && result.insertId >= 0) {
                                            cityId = result.insertId;
                                        } else {
                                            await header.rollback();
                                            let errorResult = new ResultError(400, true, "Error While Inserting City", new Error("Error While Inserting City"), '');
                                            next(errorResult);
                                        }
                                    }
                                }
                            } else {
                                //insert District
                                let districtId;
                                if (req.body.data[i].districtName) {
                                    let insertDistrictSql = `INSERT INTO districts(name, stateId) VALUES(, ` + stateId + `)`;
                                    result = await header.query(insertDistrictSql, [req.body.data[i].districtName]);
                                    if (result && result.insertId > 0) {
                                        districtId = result.insertId;
                                    } else {
                                        await header.rollback();
                                        let errorResult = new ResultError(400, true, "Error While Updating District", new Error("Error While Updating District"), '');
                                        next(errorResult);
                                    }
                                }
                                if (parseInt(req.body.data[i].cityId)) {
                                    //update City
                                    let cityId = req.body.data[i].cityId;
                                    if (req.body.data[i].cityName && req.body.data[i].pincode) {
                                        let updateCitySql = `UPDATE cities SET name = ?, districtId = ` + districtId + `, pincode = '` + req.body.data[i].pincode + `' WHERE id = ` + parseInt(cityId);
                                        result = await header.query(updateCitySql, [req.body.data[i].cityName]);
                                        if (result && result.affectedRows >= 0) {

                                        } else {
                                            await header.rollback();
                                            let errorResult = new ResultError(400, true, "Error While Updating City", new Error("Error While Updating City"), '');
                                            next(errorResult);
                                        }
                                    }
                                } else {
                                    //insert City
                                    let cityId;
                                    if (req.body.data[i].cityName && req.body.data[i].pincode) {
                                        let insertCitySql = `INSERT INTO cities(name, districtId, pincode) VALUES(?, ` + districtId + `,'` + req.body.data[i].pincode + `')`;
                                        result = await header.query(insertCitySql, [req.body.data[i].cityName]);
                                        if (result && result.insertId >= 0) {
                                            cityId = result.insertId;
                                        } else {
                                            await header.rollback();
                                            let errorResult = new ResultError(400, true, "Error While Inserting City", new Error("Error While Inserting City"), '');
                                            next(errorResult);
                                        }
                                    }
                                }
                            }
                        } else {
                            //insert State
                            let stateId;
                            if (req.body.data[i].stateName) {
                                let insertStateSql = `INSERT INTO state(name,countryId) VALUS(?, ` + countryId + `)`;
                                result = await header.query(insertStateSql, [req.body.data[i].stateName]);
                                if (result && result.insertId > 0) {
                                    stateId = result.insertId;
                                } else {
                                    await header.rollback();
                                    let errorResult = new ResultError(400, true, "Error While Insert State", new Error("Error While Insert State"), '');
                                    next(errorResult);
                                }
                            }
                            if (parseInt(req.body.data[i].districtId)) {
                                //update District
                                let districtId = req.body.data[i].districtId;
                                if (req.body.data[i].districtName) {
                                    let updateDistrictSql = `UPDATE districts SET name = ?, stateId = ` + stateId + ` WHERE id = ` + parseInt(districtId);
                                    result = await header.query(updateDistrictSql, [req.body.data[i].districtName]);
                                    if (result && result.affectedRows >= 0) {

                                    } else {
                                        await header.rollback();
                                        let errorResult = new ResultError(400, true, "Error While Updating District", new Error("Error While Updating District"), '');
                                        next(errorResult);
                                    }
                                }
                                if (parseInt(req.body.data[i].cityId)) {
                                    //update City
                                    let cityId = req.body.data[i].cityId;
                                    if (req.body.data[i].cityName && req.body.data[i].pincode) {
                                        let updateCitySql = `UPDATE cities SET name = , districtId = ` + districtId + `, pincode = '` + req.body.data[i].pincode + `' WHERE id = ` + parseInt(cityId);
                                        result = await header.query(updateCitySql, [req.body.data[i].cityName]);
                                        if (result && result.affectedRows >= 0) {

                                        } else {
                                            await header.rollback();
                                            let errorResult = new ResultError(400, true, "Error While Updating City", new Error("Error While Updating City"), '');
                                            next(errorResult);
                                        }
                                    }
                                } else {
                                    //insert City
                                    let cityId;
                                    if (req.body.data[i].cityName && req.body.data[i].pincode) {
                                        let insertCitySql = `INSERT INTO cities(name, districtId, pincode) VALUES(?, ` + districtId + `,'` + req.body.data[i].pincode + `')`;
                                        result = await header.query(insertCitySql, [req.body.data[i].cityName]);
                                        if (result && result.insertId >= 0) {
                                            cityId = result.insertId;
                                        } else {
                                            await header.rollback();
                                            let errorResult = new ResultError(400, true, "Error While Inserting City", new Error("Error While Inserting City"), '');
                                            next(errorResult);
                                        }
                                    }
                                }
                            } else {
                                //insert District
                                let districtId;
                                if (req.body.data[i].districtName) {
                                    let insertDistrictSql = `INSERT INTO districts(name, stateId) VALUES(?, ` + stateId + `)`;
                                    result = await header.query(insertDistrictSql, [req.body.data[i].districtName]);
                                    if (result && result.insertId > 0) {
                                        districtId = result.insertId;
                                    } else {
                                        await header.rollback();
                                        let errorResult = new ResultError(400, true, "Error While Updating District", new Error("Error While Updating District"), '');
                                        next(errorResult);
                                    }
                                }
                                if (parseInt(req.body.data[i].cityId)) {
                                    //update City
                                    let cityId = req.body.data[i].cityId;
                                    if (req.body.data[i].cityName && req.body.data[i].pincode) {
                                        let updateCitySql = `UPDATE cities SET name = ?, districtId = ` + districtId + `, pincode = '` + req.body.data[i].pincode + `' WHERE id = ` + parseInt(cityId);
                                        result = await header.query(updateCitySql, [req.body.data[i].cityName]);
                                        if (result && result.affectedRows >= 0) {

                                        } else {
                                            await header.rollback();
                                            let errorResult = new ResultError(400, true, "Error While Updating City", new Error("Error While Updating City"), '');
                                            next(errorResult);
                                        }
                                    }
                                } else {
                                    //insert City
                                    let cityId;
                                    if (req.body.data[i].cityName && req.body.data[i].pincode) {
                                        let insertCitySql = `INSERT INTO cities(name, districtId, pincode) VALUES(?, ` + districtId + `,'` + req.body.data[i].pincode + `')`;
                                        result = await header.query(insertCitySql, [req.body.data[i].cityName]);
                                        if (result && result.insertId >= 0) {
                                            cityId = result.insertId;
                                        } else {
                                            await header.rollback();
                                            let errorResult = new ResultError(400, true, "Error While Inserting City", new Error("Error While Inserting City"), '');
                                            next(errorResult);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                await header.commit();
                let successResult = new ResultSuccess(200, true, 'Update Region Data Successfully', result, 1, authorizationResult.token);
                return res.status(200).send(successResult);
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
        let errorResult = new ResultError(500, true, 'region.getAllRegionData() Exception', error, '');
        next(errorResult);
    }
}

export default {
    getCountries, insertCountry, updateCountry, activeInactiveCountry
    , getStates, insertState, updateState, activeInactiveState
    , getDistricts, insertDistrict, updateDistrict, activeInactiveDistrict
    , getCities, insertCity, updateCity, activeInactiveCity
    , getAllRegionData, updateRegionData
};