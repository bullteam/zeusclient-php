<?php
namespace ZeusClient\Auth;


class PermCenter {

	/**
		验证jwt所需的公钥
	**/
	const JWTPUBLICKEY = "-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC/TYKuXsgYdoICfEZOiy1L12Cb
yPdudhrCjrjwVcIrhGNn6Udq/SY5rh0ixm09I2tXPWLYuA1R55kyeo5RPFX+FrD+
mQwfJkV/QfhaPsNjU4nCEHFMtrsYCcLYJs9uX0tJdAtE6sg/VSulg1aMqCNWvtVt
jrrVXSbu4zbyWzVkxQIDAQAB
-----END PUBLIC KEY-----";
	/**
		权限接口地址
	**/
	const CENTERSERVICE = "http://api.admin.bullteam.cn";

	private $accessToken;
	private $domain;

	public function __construct($accessToken,$domain){
		$this->accessToken = $accessToken;
		$this->domain = $domain;
	}

    /**
     * 检查权限
     */
	public function checkPerm($perm){
		$perm = $this->request("user/perm/check",["domain"=>$this->domain,"perm"=>$perm],"POST");
		$perm = json_decode($perm,true);
		return $perm["code"] === 0;
	}

	private function request($service,$params=[],$method="GET"){
		$ch  = curl_init();
		curl_setopt($ch, CURLOPT_URL, self::CENTERSERVICE."/".$service);
		if(!in_array($method, ["POST","GET"],true)){
			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method); 
		}
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($ch, CURLOPT_HTTPHEADER, array('Authorization: Bearer '.$this->accessToken )); 
		if(count($params) > 0){
			curl_setopt($ch, CURLOPT_POST,true);
			curl_setopt($ch, CURLOPT_POSTFIELDS, $params); 
		}
		$content = curl_exec($ch);
		curl_close($ch);
		return $content;
	}

    /**
     * 验证
     */
    public function verify(){
        try{
            $claims = JWToken::decode($this->accessToken,self::JWTPUBLICKEY,'RS256');
            return $claims;
        }catch(\Exception $e){
            throw new LangException('app', 121000011);
        }
        if($claims->exp < time()){
            throw new LangException('app', 121000008);
        }
        return null;
    }
}