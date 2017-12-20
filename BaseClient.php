<?php
/**
 * @link http://www.tintsoft.com/
 * @copyright Copyright (c) 2012 TintSoft Technology Co. Ltd.
 * @license http://www.tintsoft.com/license/
 */

namespace xutl\alipay;

use Yii;
use yii\di\Instance;
use yii\httpclient\Client;
use yii\base\InvalidConfigException;
use yii\httpclient\RequestEvent;

/**
 * Class BaseClient
 * @package xutl\alipay
 */
abstract class BaseClient extends Client
{
    const SIGNATURE_METHOD_RSA = 'RSA';
    const SIGNATURE_METHOD_RSA2 = 'RSA2';

    /**
     * @var integer
     */
    public $appId;

    /**
     * @var string 私钥
     */
    public $privateKey;

    /**
     * @var string 公钥
     */
    public $publicKey;

    /**
     * @var string 签名方法
     */
    public $signType = self::SIGNATURE_METHOD_RSA2;

    /**
     * @var string 网关地址
     */
    public $baseUrl = 'https://openapi.alipay.com';

    /**
     * 初始化
     * @throws InvalidConfigException
     */
    public function init()
    {
        parent::init();
        if (!in_array('sha256', openssl_get_md_methods(), true)) {
            trigger_error('need openssl support sha256', E_USER_ERROR);
        }
        if (empty ($this->appId)) {
            throw new InvalidConfigException ('The "appId" property must be set.');
        }
        if (empty ($this->privateKey)) {
            throw new InvalidConfigException ('The "privateKey" property must be set.');
        }
        if (empty ($this->publicKey)) {
            throw new InvalidConfigException ('The "publicKey" property must be set.');
        }
        $privateKey = "file://" . Yii::getAlias($this->privateKey);
        $this->privateKey = openssl_pkey_get_private($privateKey);
        if ($this->privateKey === false) {
            throw new InvalidConfigException(openssl_error_string());
        }
        $publicKey = "file://" . Yii::getAlias($this->publicKey);
        $this->publicKey = openssl_pkey_get_public($publicKey);
        if ($this->publicKey === false) {
            throw new InvalidConfigException(openssl_error_string());
        }

        $this->responseConfig['format'] = Client::FORMAT_JSON;
        $this->on(Client::EVENT_BEFORE_SEND, [$this, 'RequestEvent']);
    }

    /**
     * 请求事件
     * @param RequestEvent $event
     * @return void
     */
    public function RequestEvent(RequestEvent $event)
    {
        $params = $event->request->getData();
        $params = ArrayHelper::merge([
            'app_id' => $this->appId,
            'format' => 'JSON',
            'charset' => 'utf-8',
            'sign_type' => $this->signType,
            'timestamp' => date('Y-m-d H:i:s'),
            'version' => '1.0',
        ], $params);
        $params['biz_content'] = Json::encode($params['biz_content']);
        //签名
        if ($this->signType == self::SIGNATURE_METHOD_RSA2) {
            $params['sign'] = openssl_sign($this->getSignContent($params), $sign, $this->privateKey, OPENSSL_ALGO_SHA256) ? base64_encode($sign) : null;
        } elseif ($this->signType == self::SIGNATURE_METHOD_RSA) {
            $params['sign'] = openssl_sign($this->getSignContent($params), $sign, $this->privateKey, OPENSSL_ALGO_SHA1) ? base64_encode($sign) : null;
        }
        $event->request->setData($params);
    }

    /**
     * 数据签名处理
     * @param array $toBeSigned
     * @param bool $verify
     * @return bool|string
     */
    protected function getSignContent(array $toBeSigned, $verify = false)
    {
        ksort($toBeSigned);
        $stringToBeSigned = '';
        foreach ($toBeSigned as $k => $v) {
            if ($verify && $k != 'sign' && $k != 'sign_type') {
                $stringToBeSigned .= $k . '=' . $v . '&';
            }
            if (!$verify && $v !== '' && !is_null($v) && $k != 'sign' && '@' != substr($v, 0, 1)) {
                $stringToBeSigned .= $k . '=' . $v . '&';
            }
        }
        $stringToBeSigned = substr($stringToBeSigned, 0, -1);
        unset($k, $v);
        return $stringToBeSigned;
    }

}