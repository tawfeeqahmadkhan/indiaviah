import express from 'express';
import controller from '../../controllers/app/paymentGateways';

const router = express.Router();

router.post('/getPaymentgateways',controller.getPaymentgateways);

router.post('/getPaymentgatewaysForPackage',controller.getPaymentgatewaysForPackage);

export = router;