//
// Copyright (c) SAS Institute Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

// Simple, incomplete red-black tree implementation meant only to rebuild the
// directory tree of a CDF file.
package redblack

func New(less LessFunc) *Tree {
	return &Tree{Less: less}
}

func (t *Tree) Insert(item interface{}) {
	node := &Node{Item: item, Less: t.Less}
	t.Root = t.Root.insert(node)
	t.Count++
}

func (t *Tree) Nodes() []*Node {
	if t.Root == nil {
		return nil
	}
	ret := make([]*Node, 0, t.Count)
	stack := []*Node{t.Root}
	for len(stack) > 0 {
		i := len(stack) - 1
		node := stack[i]
		stack = stack[:i]
		ret = append(ret, node)
		if node.Children[0] != nil {
			stack = append(stack, node.Children[0])
		}
		if node.Children[1] != nil {
			stack = append(stack, node.Children[1])
		}
	}
	return ret
}

type LessFunc func(i, j interface{}) bool

type Tree struct {
	Root  *Node
	Less  LessFunc
	Count uint
}

type Node struct {
	Item     interface{}
	Less     LessFunc
	Red      bool
	Children [2]*Node
}

func (n *Node) isRed() bool {
	return n != nil && n.Red
}

func (n *Node) rotate(dir int) *Node {
	a := n.Children[1-dir]
	n.Children[1-dir] = a.Children[dir]
	a.Children[dir] = n
	n.Red = true
	a.Red = false
	return a
}

func (n *Node) insert(a *Node) *Node {
	if n == nil {
		return a
	}
	dir := 0
	if n.Less(n.Item, a.Item) {
		dir = 1
	}
	n.Children[dir] = n.Children[dir].insert(a)
	if !n.Children[dir].isRed() {
		return n
	} else if n.Children[1-dir].isRed() {
		n.Red = true
		n.Children[0].Red = false
		n.Children[1].Red = false
		return n
	} else if n.Children[dir].Children[dir].isRed() {
		return n.rotate(1 - dir)
	} else if n.Children[dir].Children[1-dir].isRed() {
		n.Children[dir] = n.Children[dir].rotate(dir)
		return n.rotate(1 - dir)
	} else {
		return n
	}
}
