'use client';
import marked from 'marked';
import { useState } from 'react';

export default function Markdown({ source }: { source: string }) {
  const [html] = useState(() => marked(source));
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
