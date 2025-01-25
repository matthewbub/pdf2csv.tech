"use client";
import React, { useCallback, useEffect, useState } from "react";
import CharacterCount from "@tiptap/extension-character-count";
import Blockquote from "@tiptap/extension-blockquote";
import BulletList from "@tiptap/extension-bullet-list";
import HardBreak from "@tiptap/extension-hard-break";
import Heading from "@tiptap/extension-heading";
import HorizontalRule from "@tiptap/extension-horizontal-rule";
import Image from "@tiptap/extension-image";
import Link from "@tiptap/extension-link";
import ListItem from "@tiptap/extension-list-item";
import OrderedList from "@tiptap/extension-ordered-list";
import Strike from "@tiptap/extension-strike";
import Underline from "@tiptap/extension-underline";
import Code from "@tiptap/extension-code";
import { EditorContent, useEditor } from "@tiptap/react";
import StarterKit from "@tiptap/starter-kit";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Button, ButtonDiv } from "@/components/ui/button";
import {
  BoldIcon,
  CodeIcon,
  ImageIcon,
  ItalicIcon,
  Link2Icon,
  Link2OffIcon,
  List,
  Strikethrough,
  UnderlineIcon,
} from "lucide-react";
import { debounce, cn } from "@/lib/utils";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectSeparator,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import css from "highlight.js/lib/languages/css";
import js from "highlight.js/lib/languages/javascript";
import ts from "highlight.js/lib/languages/typescript";
import html from "highlight.js/lib/languages/xml";
import hljs from "highlight.js/lib/core";
import go from "highlight.js/lib/languages/go";
import "highlight.js/styles/github-dark.css";

// load all highlight.js languages
import CodeBlockLowlight from "@tiptap/extension-code-block-lowlight";
import { all, createLowlight } from "lowlight";
import { Controller, useForm } from "react-hook-form";

const lowlight = createLowlight(all);
hljs.registerLanguage("css", css);
hljs.registerLanguage("javascript", js);
hljs.registerLanguage("typescript", ts);
hljs.registerLanguage("xml", html);
hljs.registerLanguage("go", go);

export const proseClassNames = cn([
  "prose:w-full prose-sm md:prose-base dark:prose-invert prose-custom p-1",
  "h-full max-w-full prose-ol:list-decimal prose-ul:list-disc",
  "prose-a:text-blue-500 prose-a:underline",
  "prose-pre:bg-stone-800 prose-pre:text-stone-50 prose-pre:rounded-md prose-pre:px-4 prose-pre:py-2 prose-pre:leading-3",
  "prose-p:leading-5 prose-p:text-stone-700 dark:prose-p:text-stone-400",
  "dark:prose-strong:text-white prose-strong:text-black",
  "prose-code:bg-stone-800 prose-code:text-stone-50 prose-code:rounded-sm prose-code:px-1.5 prose-code:py-0.5 prose-code:leading-3 md:prose-code:leading-4",
  "prose-headings:text-stone-950 dark:prose-headings:text-white prose-headings:font-bold prose-headings:tracking-tight prose-headings:leading-tight prose-headings:mb-4 prose-headings:mt-8",
  "prose-hr:border-stone-900/10 dark:prose-hr:border-stone-700/50",
]);

const TipTap = ({
  defaultValue,
  params,
  editable = true,
  callback,
}: {
  defaultValue?: string;
  params?: {
    slug: string;
  };
  editable?: boolean;
  className?: string;
  callback?: (content: string) => void;
}) => {
  const { control, setValue } = useForm();
  const [classNameFromState, setClassNameFromState] = useState(proseClassNames);

  const editor = useEditor({
    editable: editable,
    editorProps: {
      attributes: {
        class: classNameFromState,
      },
    },
    extensions: [
      StarterKit.configure({
        heading: false,
        strike: false,
        codeBlock: false,
        bulletList: false,
        orderedList: false,
        blockquote: false,
        hardBreak: false,
        horizontalRule: false,
        listItem: false,
        code: false,
      }),
      Underline,
      Link.configure({
        openOnClick: false,
        autolink: true,
      }),
      Strike,
      Image,
      Blockquote,
      BulletList,
      ListItem,
      CodeBlockLowlight.configure({
        lowlight,
      }),
      HardBreak,
      Heading.configure({
        levels: [1, 2, 3],
      }),
      HorizontalRule,
      OrderedList,
      CharacterCount,
      Code,
    ],
    content: defaultValue || "",
  });

  const debouncedUpdate = useCallback(
    debounce(async (content: string) => {
      try {
        if (callback) {
          callback(content);
        }
        console.log("content", content);
      } catch (e) {
        console.error(e);
        setClassNameFromState(
          proseClassNames + " border-red-500 border-2 border-solid"
        );
      }
    }, 100),
    [params?.slug]
  );

  useEffect(() => {
    if (!editor) {
      return;
    }

    editor.on("update", ({ editor }: any) => {
      if (!params?.slug) return;

      const content = editor.getHTML();
      debouncedUpdate(content);
    });
  }, [editor, debouncedUpdate]);

  useEffect(() => {
    if (!editor) return;

    const updateSelectValue = () => {
      const { $anchor } = editor.state.selection;
      const node = $anchor.node($anchor.depth);
      let value = "Body (normal)";

      if (node.type.name === "heading") {
        value = `Heading ${node.attrs.level}`;
      } else if (node.type.name === "blockquote") {
        value = "Blockquote";
      } else if (node.type.name === "codeBlock") {
        value = "Code Block";
      } else if (node.type.name === "paragraph") {
        value = "Body (normal)";
      }

      setValue("text", value);
    };

    editor.on("selectionUpdate", updateSelectValue);

    return () => {
      editor.off("selectionUpdate", updateSelectValue);
    };
  }, [editor, setValue]);

  const setLink = useCallback(() => {
    if (!editor) {
      return;
    }

    const previousUrl = editor.getAttributes("link").href;
    const url = window.prompt("URL", previousUrl);

    // cancelled
    if (url === null) {
      return;
    }

    // empty
    if (url === "") {
      editor.chain().focus().extendMarkRange("link").unsetLink().run();

      return;
    }

    // update link
    editor.chain().focus().extendMarkRange("link").setLink({ href: url }).run();
  }, [editor]);

  const addImage = useCallback(() => {
    const url = window.prompt("URL");

    if (url) {
      if (!editor) {
        return;
      }

      editor.chain().focus().setImage({ src: url }).run();
    }
  }, [editor]);

  if (!editor) {
    return null;
  }

  return (
    <div className="h-[calc(100vh-56px)]">
      {editable && (
        <div className="sticky top-0 z-10 flex flex-wrap items-center gap-1 border-b border-accent bg-card pb-2 pt-1">
          <Controller
            name="text"
            control={control}
            render={({ field: { onChange, value } }) => (
              <Select
                value={value}
                onValueChange={(value) => {
                  onChange(value);
                  switch (value) {
                    case "Heading 1":
                      editor.chain().focus().toggleHeading({ level: 1 }).run();
                      break;
                    case "Heading 2":
                      editor.chain().focus().toggleHeading({ level: 2 }).run();
                      break;
                    case "Heading 3":
                      editor.chain().focus().toggleHeading({ level: 3 }).run();
                      break;
                    case "Heading 4":
                      editor.chain().focus().toggleHeading({ level: 4 }).run();
                      break;
                    case "Heading 5":
                      editor.chain().focus().toggleHeading({ level: 5 }).run();
                      break;
                    case "Heading 6":
                      editor.chain().focus().toggleHeading({ level: 6 }).run();
                      break;
                    case "Code Block":
                      editor.chain().focus().toggleCodeBlock().run();
                      break;
                    case "Blockquote":
                      editor.chain().focus().toggleBlockquote().run();
                      break;
                    case "Body (normal)":
                      editor.chain().focus().clearNodes().run();
                      break;
                    case "Clear Formatting":
                      editor.chain().focus().unsetAllMarks().run();
                      editor.chain().focus().clearNodes().run();
                      break;
                    default:
                      break;
                  }
                }}
              >
                <SelectTrigger className="flex w-[150px] items-center justify-between">
                  <SelectValue placeholder={"Select text"} />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="Body (normal)">Body (normal)</SelectItem>
                  <SelectSeparator />
                  {[
                    "Heading 1",
                    "Heading 2",
                    "Heading 3",
                    "Heading 4",
                    "Heading 5",
                    "Heading 6",
                  ].map((heading) => (
                    <SelectItem key={heading} value={heading}>
                      {heading}
                    </SelectItem>
                  ))}
                  <SelectSeparator />
                  {["Blockquote", "Code Block"].map((block) => (
                    <SelectItem key={block} value={block}>
                      {block}
                    </SelectItem>
                  ))}
                  <SelectSeparator />
                  <SelectItem value="Clear">Clear Formatting</SelectItem>
                </SelectContent>
              </Select>
            )}
          />
          <Button
            size={"icon"}
            variant={"ghost"}
            onClick={() => editor.chain().focus().toggleBold().run()}
            disabled={!editor.can().chain().focus().toggleBold().run()}
            className={
              editor.isActive("bold") ? "bg-accent text-accent-foreground" : ""
            }
          >
            <BoldIcon className="h-5 w-5" />
            <span className="sr-only">Bold</span>
          </Button>
          <Button
            size={"icon"}
            variant={"ghost"}
            onClick={() => editor.chain().focus().toggleItalic().run()}
            disabled={!editor.can().chain().focus().toggleItalic().run()}
            className={
              editor.isActive("italic")
                ? "bg-accent text-accent-foreground"
                : ""
            }
          >
            <ItalicIcon className="h-5 w-5" />
            <span className="sr-only">Italic</span>
          </Button>
          <Button
            size={"icon"}
            variant={"ghost"}
            onClick={() => editor.chain().focus().toggleUnderline().run()}
            disabled={!editor.can().chain().focus().toggleUnderline().run()}
            className={
              editor.isActive("underline")
                ? "bg-accent text-accent-foreground"
                : ""
            }
          >
            <UnderlineIcon className="h-5 w-5" />
            <span className="sr-only">Underline</span>
          </Button>

          <Button
            size={"icon"}
            variant={"ghost"}
            onClick={() => editor.chain().focus().toggleStrike().run()}
            className={
              editor.isActive("strike")
                ? "bg-accent text-accent-foreground"
                : ""
            }
          >
            <Strikethrough className="h-5 w-5" />
            <span className="sr-only">Strike</span>
          </Button>

          {editor.isActive("link") ? (
            <Button
              size={"icon"}
              variant={"ghost"}
              onClick={() => editor.chain().focus().unsetLink().run()}
            >
              <Link2OffIcon className="h-5 w-5" />
              <span className="sr-only">Unset Link</span>
            </Button>
          ) : (
            <Button size={"icon"} variant={"ghost"} onClick={setLink}>
              <Link2Icon className="h-5 w-5" />
              <span className="sr-only">Link</span>
            </Button>
          )}
          <Button
            size={"icon"}
            variant={"ghost"}
            onClick={addImage}
            className={
              editor.isActive("image") ? "bg-accent text-accent-foreground" : ""
            }
          >
            <ImageIcon className="h-5 w-5" />
            <span className="sr-only">Image</span>
          </Button>
          <Button
            size={"icon"}
            variant={"ghost"}
            onClick={() => editor.chain().focus().toggleCode().run()}
            className={
              editor.isActive("code") ? "bg-accent text-accent-foreground" : ""
            }
          >
            <CodeIcon className="h-5 w-5" />
            <span className="sr-only">Code</span>
          </Button>
          <DropdownMenu>
            <DropdownMenuTrigger>
              <ButtonDiv
                role="div"
                size={"icon"}
                variant={"ghost"}
                className={
                  editor.isActive("bulletList")
                    ? "bg-accent text-accent-foreground"
                    : ""
                }
              >
                <List className="h-5 w-5" />
                <span className="sr-only">Bullet List</span>
              </ButtonDiv>
            </DropdownMenuTrigger>
            <DropdownMenuContent>
              <DropdownMenuItem
                className={
                  editor.isActive("bulletList")
                    ? "bg-accent text-accent-foreground"
                    : ""
                }
                onSelect={() => editor.chain().focus().toggleBulletList().run()}
              >
                Bullet List
              </DropdownMenuItem>
              <DropdownMenuItem
                className={
                  editor.isActive("orderedList")
                    ? "bg-accent text-accent-foreground"
                    : ""
                }
                onSelect={() =>
                  editor.chain().focus().toggleOrderedList().run()
                }
              >
                Ordered List
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      )}
      <div className="mb-4 mt-1 h-[calc(100vh-200px)]" id="tiptap">
        <EditorContent editor={editor} />
      </div>
      {editable && (
        <div
          className={cn([
            "border-t border-accent py-3 text-sm text-muted-foreground",
            "flex justify-end ",
          ])}
        >
          <span>{editor.storage.characterCount.characters()} characters</span>
          <span className="mx-2">|</span>
          <span>{editor.storage.characterCount.words()} words</span>
        </div>
      )}
    </div>
  );
};

export default TipTap;
