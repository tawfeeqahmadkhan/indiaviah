import express from 'express';
import controller from '../../controllers/app/currency';

const router = express.Router();

router.post('/getDefaultCurrency',controller.getDefaultCurrency);

export = router;