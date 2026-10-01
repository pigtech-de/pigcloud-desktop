<?php

class FontConfig
{
    public const array FONTS = [
        "default" => [
            "displayName" => "Browser Default",
            "translateKey" => "fontDefault",
            "fileName" => null,
            "fallback" => "serif"
        ],
        "annotation" => [
            "displayName" => "Annotation Mono",
            "translateKey" => "fontAnnotation",
            "fileName" => "annotation-mono.woff2",
            "fallback" => "monospace"
        ],
        "plex_mono" => [
            "displayName" => "IBM Plex Mono",
            "translateKey" => "fontPlexMono",
            "fileName" => "plex-mono.woff2",
            "fallback" => "monospace"
        ],
        "jetbrains_mono" => [
            "displayName" => "JetBrains Mono",
            "translateKey" => "fontJetBrainsMono",
            "fileName" => "jetbrains-mono.woff2",
            "fallback" => "monospace"
        ],
        "standard" => [
            "displayName" => "Courier New",
            "translateKey" => "fontStandard",
            "fileName" => null,
            "fallback" => '"Courier New", Courier, monospace'
        ],
        "open_dyslexic" => [
            "displayName" => "OpenDyslexic",
            "translateKey" => "fontOpenDyslexic",
            "fileName" => "open-dyslexic.woff2",
            "fallback" => '"Helvetica Neue", Arial, sans-serif'
        ]
    ];

    public const string DEFAULT_FONT = "jetbrains_mono";

    public static function getAllowedKeys(): array
    {
        return array_keys(self::FONTS);
    }

}
