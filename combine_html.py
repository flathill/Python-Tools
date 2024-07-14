# combine_html.py
import os
import argparse

def combine_html_files(directory, outfile):
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.html'):
                filepath = os.path.join(root, file)
                with open(filepath, 'r', encoding='utf-8') as infile:
                    outfile.write(f"\n<!-- ***** FILE PATH: {filepath} ***** -->\n")
                    outfile.write(infile.read())
                    outfile.write(f"\n<!-- ***** END FILE ***** -->\n")

def main():
    parser = argparse.ArgumentParser(description='Combine HTML files into a single file.')
    parser.add_argument('input_dir', type=str, help='The root directory of HTML files to combine.')
    parser.add_argument('output_file', type=str, help='The output file to save the combined HTML content.')

    args = parser.parse_args()

    with open(args.output_file, 'w', encoding='utf-8') as outfile:
        combine_html_files(args.input_dir, outfile)

    print(f"All HTML files have been combined into {args.output_file}")

if __name__ == '__main__':
    main()
