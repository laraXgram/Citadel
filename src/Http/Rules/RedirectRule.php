<?php

namespace LaraGram\Citadel\Http\Rules;

use Closure;
use LaraGram\Contracts\Validation\ValidationRule;

class RedirectRule implements ValidationRule
{
    /**
     * Run the validation rule: a comma separated list of absolute URIs.
     *
     * @param  \Closure(string): \LaraGram\Translation\PotentiallyTranslatedString  $fail
     */
    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        foreach (explode(',', (string) $value) as $redirect) {
            if (! filter_var(trim($redirect), FILTER_VALIDATE_URL)) {
                $fail('One or more redirects have an invalid URI format.');

                return;
            }
        }
    }
}
