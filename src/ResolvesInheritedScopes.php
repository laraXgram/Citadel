<?php

namespace LaraGram\Citadel;

trait ResolvesInheritedScopes
{
    /**
     * Determine if the given ability is granted by the given list ("*" grants everything).
     *
     * @param  string[]  $granted
     */
    protected function grants(string $ability, array $granted): bool
    {
        return in_array('*', $granted, true) || $this->scopeExistsIn($ability, $granted);
    }

    /**
     * Check if a scope exists in a list of scopes, considering inheritance.
     *
     * @param  string[]  $haystack
     */
    protected function scopeExistsIn(string $scope, array $haystack): bool
    {
        $scopes = Citadel::$withInheritedScopes
            ? $this->resolveInheritedScopes($scope)
            : [$scope];

        foreach ($scopes as $scope) {
            if (in_array($scope, $haystack, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Resolve all possible scopes, from "a:b:c" to "a", "a:b" and "a:b:c".
     *
     * @return string[]
     */
    protected function resolveInheritedScopes(string $scope): array
    {
        $parts = explode(':', $scope);

        $partsCount = count($parts);

        $scopes = [];

        for ($i = 1; $i <= $partsCount; $i++) {
            $scopes[] = implode(':', array_slice($parts, 0, $i));
        }

        return $scopes;
    }
}
