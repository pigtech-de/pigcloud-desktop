<?php

declare(strict_types=1);

final class AuthPresentation
{
    public static function render(string $title, string $subtitle, string $bodyHtml, array $attributes = [], string $titleKey = '', string $subtitleKey = ''): string
    {
        $encoded = '';
        foreach ($attributes as $name => $value) {
            if ($name !== 'id' && preg_match('/^data-[a-z][a-z0-9-]*$/', $name) !== 1) {
                throw new InvalidArgumentException('Auth presentation attributes must be id or data attributes.');
            }
            $encoded .= ' ' . $name . '="' . self::escape($value) . '"';
        }
        $titleAttribute = $titleKey !== '' ? ' data-translate-key="' . self::escape($titleKey) . '"' : '';
        $subtitleAttribute = $subtitleKey !== '' ? ' data-translate-key="' . self::escape($subtitleKey) . '"' : '';
        $description = $subtitle !== '' ? '<p class="auth-sub"' . $subtitleAttribute . '>' . self::escape($subtitle) . '</p>' : '';
        return '<div class="auth-shell"><div class="auth-col vstack"><section class="card auth-card"' . $encoded . '>'
            . '<div class="auth-head vstack"><span class="logo-icon auth-brand" aria-hidden="true">'
            . '<img src="/global/icons/logo-light.svg" alt="" class="logo-light" width="48" height="48">'
            . '<img src="/global/icons/logo-dark.svg" alt="" class="logo-dark" width="48" height="48">'
            . '</span><h1 class="auth-title"' . $titleAttribute . '>' . self::escape($title) . '</h1>' . $description . '</div>'
            . '<div class="form-layout">' . $bodyHtml . '</div></section></div></div>';
    }

    public static function details(array $rows): string
    {
        $html = '<dl class="form-layout">';
        foreach ($rows as $label => $value) {
            $html .= '<div class="form-field vstack"><dt class="form-label">' . self::escape($label)
                . '</dt><dd class="text-body text-truncate" title="' . self::escape($value) . '">' . self::escape($value) . '</dd></div>';
        }
        return $html . '</dl>';
    }

    private static function escape(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}
