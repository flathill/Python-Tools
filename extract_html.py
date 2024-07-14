# split_html.py
import os
import re
import argparse

def split_html_file(input_file, output_root_dir):
    # 入力ファイルを開く
    with open(input_file, 'r', encoding='utf-8') as infile:
        content = infile.read()

    # ファイルのセパレータで分割
    sections = re.split(r'<!-- \*\*\*\*\* (FILE PATH|END FILE): (.+?) \*\*\*\*\* -->', content)

    # 各セクションを元のファイル名とパスで保存
    current_file = None
    for i in range(1, len(sections), 3):
        marker = sections[i].strip()
        filepath = sections[i + 1].strip()
        html_content = sections[i + 2]
        
        if marker == "FILE PATH":
            current_file = filepath
            output_path = os.path.join(output_root_dir, current_file)
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as outfile:
                outfile.write(html_content)
        elif marker == "END FILE" and current_file == filepath:
            output_path = os.path.join(output_root_dir, current_file)
            with open(output_path, 'a', encoding='utf-8') as outfile:
                outfile.write(html_content)

def main():
    parser = argparse.ArgumentParser(description='Split translated HTML file into individual files with original directory structure.')
    parser.add_argument('input_file', type=str, help='The translated HTML file to split.')
    parser.add_argument('output_dir', type=str, help='The root directory to save the split HTML files.')
    
    args = parser.parse_args()
    
    split_html_file(args.input_file, args.output_dir)
    
    print("Translated HTML files have been split into individual files with original directory structure.")

if __name__ == '__main__':
    main()
