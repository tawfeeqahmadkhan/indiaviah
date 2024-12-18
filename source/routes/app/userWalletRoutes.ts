import express from 'express';
import controller from '../../controllers/app/userWallet';

const router = express.Router();

// #region /api/app/userWallet/insertUserWallet apidoc
/**
 * @api {post} /api/app/userWallet/insertUserWallet Insert Amount in User Wallet
 * @apiVersion 1.0.0
 * @apiName Insert Amount in User Wallet
 * @apiDescription Insert Amount in User Wallet
 * @apiGroup User Wallet - App
 * @apiParam {string}                paymentMode                        Require paymentMode.
 * @apiParam {string}                paymentRefrence                    Require paymentRefrence.
 * @apiParam {number}                amount                             Require Amount.
 * @apiParam {string}                paymentStatus                      Require paymentStatus.
 * @apiParamExample {json} Request-Example:
 *  {
 *       "paymentMode": "Payment Mode",
 *       "paymentRefrence": "Payment Reference"
 *       "amount": 150
 *       "paymentStatus": "Success"
 *  }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Insert User Wallet",
 *         "recordList": {
 *             "fieldCount": 0,
 *             "affectedRows": 1,
 *             "insertId": 3,
 *             "serverStatus": 2,
 *             "warningCount": 0,
 *             "message": "",
 *             "protocol41": true,
 *             "changedRows": 0
 *         },
 *         "totalRecords": 1,
 *         "token": ""
 *     }
 * @apiError (500) {JSON} Result message, apiName, apiType, fileName, functionName, lineNumber, typeName, stack.
 * @apiErrorExample {json} Error-500-Response:
 *     HTTP/1.1 500 ERROR
 *     {
 *          status: <error status code>,
 *          isDisplayMessage: <true/false>, // if the value is true then display message on screen
 *          message: <error message>,
 *          error: {
 *              apiName: <api name>,
 *              apiType: <api type>,
 *              fileName: <file name>,
 *              functionName: <function name>,
 *              lineNumber: <line number>,
 *              typeName: <type name>,
 *              stack: <stack>
 *          },
 *          value: <value if any>
 *     }
 */
// #endregion
router.post('/insertUserWallet', controller.insertUserWallet);

// #region /api/app/userWallet/getUserWalletHistory apidoc
/**
 * @api {post} /api/app/userWallet/getUserWalletHistory Get User Wallet History
 * @apiVersion 1.0.0
 * @apiName Get User Wallet History
 * @apiDescription Get User Wallet History
 * @apiGroup User Wallet - App
 * @apiParam {boolean}               isHistory                          Require true if get add history; false if get spent history.
 * @apiParamExample {json} Request-Example:
 *  {
 *       "isHistory": "true/false"
 *  }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Get User Wallet History Successfully",
 *         "recordList": [
 *             {
 *                 "id": 1,
 *                 "userWalletId": 1,
 *                 "amount": 150,
 *                 "isCredit": 1/0,
 *                 "transactionDate": 2024-1-20T08:41:47.000Z,
 *                 "remark": "",
 *                 "paymentId": 1/null,
 *                 "paymentMode": "",
 *                 "paymentStatus": "",
 *                 "isActive": 1,
 *                 "isDelete": 0,
 *                 "createdDate": "2022-10-15T08:41:47.000Z",
 *                 "modifiedDate": "2022-10-15T08:41:47.000Z",
 *                 "createdBy": 6,
 *                 "modifiedBy": 6
 *             },....
 *         ],
 *         "totalRecords": 6,
 *         "token": ""
 *     }
 * @apiError (500) {JSON} Result message, apiName, apiType, fileName, functionName, lineNumber, typeName, stack.
 * @apiErrorExample {json} Error-500-Response:
 *     HTTP/1.1 500 ERROR
 *     {
 *          status: <error status code>,
 *          isDisplayMessage: <true/false>, // if the value is true then display message on screen
 *          message: <error message>,
 *          error: {
 *              apiName: <api name>,
 *              apiType: <api type>,
 *              fileName: <file name>,
 *              functionName: <function name>,
 *              lineNumber: <line number>,
 *              typeName: <type name>,
 *              stack: <stack>
 *          },
 *          value: <value if any>
 *     }
 */
// #endregion
router.post('/getUserWalletHistory', controller.getUserWalletHistory);

export = router;