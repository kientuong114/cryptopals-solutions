from collections import Counter

if __name__ == "__main__":
    with open('8.in', 'r') as f:
        cptxs = f.readlines()
    for idxs, cptx in enumerate(cptxs):
        c = Counter([cptx[i:i+32] for i in range(0, len(cptx), 32)])
        if c.most_common(1)[0][1] >= 2:
            print("ECB found in...")
            print(cptx)
            break
