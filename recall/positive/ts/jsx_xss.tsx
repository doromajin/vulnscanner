import React from "react";

interface PageProps {
    searchParams: { content: string };
}

export default function Page({ searchParams }: PageProps) {
    const content = searchParams.content;
    // TSAST-XSS-001: user input (searchParams) in dangerouslySetInnerHTML
    return <div dangerouslySetInnerHTML={{ __html: content }} />;
}
