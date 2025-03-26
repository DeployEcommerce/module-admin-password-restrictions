<?php

namespace DeployEcommerce\AdminPasswordRestrictions\Model;

use \Magento\Framework\App\Config\ScopeConfigInterface;
use Magento\Framework\Validator\DataObject;
use Magento\Framework\Validator\NotEmpty;
use Magento\Framework\Validator\Regex;
use Magento\Framework\Validator\StringLength;

/**
 * Class for adding validation rules to an Admin user
 *
 * @api
 * @since 100.0.2
 */
class UserValidationRules extends \Magento\User\Model\UserValidationRules
{
    const CONFIG_ADMIN_SECURITY_MINIMUM_PASSWORD_LENGTH = 'admin/security/minimum_password_length';
    private ScopeConfigInterface $scopeConfig;

    public function __construct(ScopeConfigInterface $scopeConfig)
    {
        $this->scopeConfig = $scopeConfig;
    }

    /**
     * Adds validation rule for user password
     *
     * @param DataObject $validator
     * @return DataObject
     */
    public function addPasswordRules(DataObject $validator)
    {
        $passwordNotEmpty = new NotEmpty();
        $passwordNotEmpty->setMessage(__('Password is required field.'), NotEmpty::IS_EMPTY);
        $minPassLength = $this->scopeConfig->getValue(self::CONFIG_ADMIN_SECURITY_MINIMUM_PASSWORD_LENGTH);
        $passwordLength = new StringLength(['min' => $minPassLength, 'encoding' => 'UTF-8']);
        $passwordLength->setMessage(
            __('Your password must be at least %1 characters.', $minPassLength),
            StringLength::TOO_SHORT
        );
        $passwordChars = new Regex('/[a-z].*\d|\d.*[a-z]/iu');
        $passwordChars->setMessage(
            __('Your password must include both numeric and alphabetic characters.'),
            Regex::NOT_MATCH
        );
        $validator->addRule(
            $passwordNotEmpty,
            'password'
        )->addRule(
            $passwordLength,
            'password'
        )->addRule(
            $passwordChars,
            'password'
        );

        return $validator;
    }
}
