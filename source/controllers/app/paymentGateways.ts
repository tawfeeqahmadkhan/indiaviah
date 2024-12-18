import { NextFunction, Request, Response } from 'express';
import logging from "../../config/logging";
import config from "../../config/config";
import header from "../../middleware/apiHeader";
import { ResultSuccess } from '../../classes/response/resultsuccess';
import { ResultError } from '../../classes/response/resulterror';

const NAMESPACE = 'Payment Gateways';

const getPaymentgateways = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Payment Gateways');
        let requiredFields = [''];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let sql = `SELECT pg.* FROM paymentgateway pg INNER JOIN currencypaymentgateway cpg ON pg.id = cpg.paymentGatewayId  INNER JOIN currencies c ON cpg.currencyId = c.id WHERE c.isDefault = 1 AND pg.isActive = 1 AND pg.useInWallet = 1`;
                // if (req.body.isWallet != null || req.body.isWallet == true || req.body.isWallet == false) {
                //     sql += " AND pg.useInWallet = " + req.body.isWallet;
                // }
                let result = await header.query(sql);
                console.log(result)
                if (result && result.length >= 0) {
                    let data = [];
                    for (let i = 0; i < result.length; i++) {
                        let obj = {
                            id: result[i].id,
                            name: result[i].name,
                            jsonData: JSON.parse(result[i].jsonData),
                            useInWallet: result[i].useInWallet,
                            useInCheckout: result[i].useInCheckout,
                            useInAndroid: result[i].useInAndroid,
                            useInApple: result[i].useInApple,
                            isActive: result[i].isActive,
                            isDelete: result[i].isDelete,
                            createdDate: result[i].createdDate,
                            modifiedDate: result[i].modifiedDate,
                            createdBy: result[i].createdBy,
                            modifiedBy: result[i].modifiedBy,
                        }

                        data.push(obj)
                    }
                    let successResult = new ResultSuccess(200, true, 'Get Payment Gateways', data, data.length, '');
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "paymentGateways.getPaymentgateways() Error", new Error('Error While Updating Data'), '');
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
        let errorResult = new ResultError(500, true, 'paymentGateways.getPaymentgateways() Exception', error, '');
        next(errorResult);
    }
}

const getPaymentgatewaysForPackage = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Payment Gateways');
        let requiredFields = [''];
        // let validationResult = header.validateRequiredFields(req, requiredFields);
        // if (validationResult && validationResult.statusCode == 200) {
        //     let authorizationResult = await header.validateAuthorization(req, res, next);
        //     if (authorizationResult.statusCode == 200) {
        let sql = `SELECT pg.* FROM paymentgateway pg INNER JOIN currencypaymentgateway cpg ON pg.id = cpg.paymentGatewayId  INNER JOIN currencies c ON cpg.currencyId = c.id WHERE c.isDefault = 1 AND pg.isActive = 1`;
        // if (req.body.isWallet != null || req.body.isWallet == true || req.body.isWallet == false) {
        //     sql += " AND pg.useInWallet = " + req.body.isWallet;
        // }
        if (req.body != null && req.body.appPlatform == "iosApp") {
            sql += ` AND useInApple = 1`
        }
        else if (req.body != null && req.body.appPlatform == "androidApp") {
            sql += ` AND useInAndroid = 1`
        }
        let result = await header.query(sql);
        console.log(result)
        if (result && result.length >= 0) {
            let data = [];
            for (let i = 0; i < result.length; i++) {
                let obj = {
                    id: result[i].id,
                    name: result[i].name,
                    jsonData: JSON.parse(result[i].jsonData),
                    useInWallet: result[i].useInWallet,
                    useInCheckout: result[i].useInCheckout,
                    useInAndroid: result[i].useInAndroid,
                    useInApple: result[i].useInApple,
                    isActive: result[i].isActive,
                    isDelete: result[i].isDelete,
                    createdDate: result[i].createdDate,
                    modifiedDate: result[i].modifiedDate,
                    createdBy: result[i].createdBy,
                    modifiedBy: result[i].modifiedBy,
                }

                data.push(obj)
            }
            let successResult = new ResultSuccess(200, true, 'Get Payment Gateways For Package', data, data.length, '');
            return res.status(200).send(successResult);
        } else {
            let errorResult = new ResultError(400, true, "paymentGateways.getPaymentgatewaysForPackage() Error", new Error('Error While Updating Data'), '');
            next(errorResult);
        }
        // } else {
        //     let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
        //     next(errorResult);
        // }
        // } else {
        //     let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
        //     next(errorResult);
        // }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'paymentGateways.getPaymentgatewaysForPackage() Exception', error, '');
        next(errorResult);
    }
}

export default { getPaymentgateways, getPaymentgatewaysForPackage };