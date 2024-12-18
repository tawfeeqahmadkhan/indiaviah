import express from 'express';
import controller from '../../controllers/admin/paymentgateway';

const router = express.Router();

// #region /api/admin/paymentGateways/getpaymentGateway apidoc
/**
 * @api {post} /api/admin/paymentGateways/getpaymentGateway Get Currencies
 * @apiVersion 1.0.0
 * @apiName Get paymentGateway
 * @apiDescription Get paymentGateway
 * @apiGroup paymentGateway - Admin
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Get paymentGateway Successfully",
 *         "recordList": [
 *             {
 *                 "id": 1,
 *                 "name": "Rupees",
 *                 "symbol": "₹",
 *                 "code": "INR",
 *                 "isDefault": 1,
 *                 "isActive": 1,
 *                 "isDelete": 0,
 *                 "createdDate": "2022-10-14T07:04:39.000Z",
 *                 "modifiedDate": "2022-10-14T07:04:39.000Z",
 *                 "createdBy": 1,
 *                 "modifiedBy": 1
 *             },....
 *         ],
 *         "totalRecords": 11,
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
router.post('/getpaymentGateway', controller.getPaymentGateway);

// #region /api/admin/paymentGateways/activeInactivePaymentGateway apidoc
/**
 * @api {post} /api/admin/paymentGateways/activeInactivePaymentGateway Active/InActive Payment Gateway
 * @apiVersion 1.0.0
 * @apiName Active/InActive Payment Gateway
 * @apiDescription Active/InActive Payment Gateway
 * @apiGroup paymentGateway - Admin
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Active/InActive Payment Gateway Successfully",
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
router.post('/activeInActivePaymentGateway', controller.activeInactivePaymentGateway);

// #region /api/admin/paymentGateways/updatePaymentGateway apidoc
/**
 * @api {post} /api/admin/paymentGateways/updatePaymentGateway Update Payment Gateway Key
 * @apiVersion 1.0.0
 * @apiName Update Payment Gateway Key
 * @apiDescription Update Payment Gateway Key
 * @apiGroup paymentGateway - Admin
 * @apiParamExample {json} Request-Example:
 *      {
 *           "id": 2,
 *           "json":""
 *      }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Update Payment Gateway Successfully",
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
router.post('/updatePaymentGateway', controller.updatePaymentGateway);

export = router;
