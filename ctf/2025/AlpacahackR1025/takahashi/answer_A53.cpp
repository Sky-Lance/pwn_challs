// https://github.com/E869120/kyopro-tessoku/blob/main/codes/cpp/chap08/answer_A53.cpp
#include <iostream>
#include <queue>
#include <vector>
using namespace std;

int Q;
int QueryType[100009], x[100009];
priority_queue<int, vector<int>, greater<int>> T;

int main() {
	// 入力
	cin >> Q;
	for (int i = 1; i <= Q; i++) {
		cin >> QueryType[i];
		if (QueryType[i] == 1) cin >> x[i];
	}

	// クエリの処理
	for (int i = 1; i <= Q; i++) {
		if (QueryType[i] == 1) T.push(x[i]);
		if (QueryType[i] == 2) cout << T.top() << endl;
		if (QueryType[i] == 3) T.pop();
	}
	return 0;
}

void win() { std::system("/bin/sh"); } // Gift :)
